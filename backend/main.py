import json
import logging
import re
import requests
import paramiko
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Tuple
import subprocess
import os
import tempfile
import shutil
from io import StringIO

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

origins = [
    "http://localhost:8888",
    "http://127.0.0.1:8888",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_config: Dict = {}

class CommitInfo(BaseModel):
    hash: str
    message: str

class DeployRequest(BaseModel):
    commit_hash: str

def load_config_on_startup():
    """Загрузка конфигурации из JSON файла при старте приложения."""
    global _config
    try:
        with open("config.json", "r") as f:
            _config = json.load(f)
        logger.info("Конфигурация успешно загружена.")
        if not _config.get("repositories"):
            logger.warning("В config.json отсутствует или пуста секция 'repositories'.")
    except FileNotFoundError:
        logger.error("Ошибка: config.json не найден. Убедитесь, что он расположен в корневой директории приложения (backend/).")
        _config = {"repositories": []}
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка: Неверный формат JSON в config.json: {e}. Проверьте синтаксис файла.")
        _config = {"repositories": []}
    except Exception as e:
        logger.error(f"Неизвестная ошибка при загрузке config.json: {e}")
        _config = {"repositories": []}

@app.on_event("startup")
async def startup_event():
    load_config_on_startup()

def _execute_remote_command(ssh_client: paramiko.SSHClient, command: str, error_message: str, output_log: List[str], prepend_commands: Optional[str] = None) -> Tuple[str, str]:
    """
    Выполняет команду на удаленном сервере через SSH и обрабатывает вывод.
    Возвращает (stdout, stderr). Вызывает исключение при ошибке.
    """
    full_command = f"{prepend_commands} && {command}" if prepend_commands else command
    logger.info(f"Выполнение команды: {full_command}")
    stdin, stdout, stderr = ssh_client.exec_command(full_command)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    exit_status = stdout.channel.recv_exit_status()

    output_log.append(f"Команда: {full_command}")
    if out:
        output_log.append(f"STDOUT:\n{out}")
    if err:
        output_log.append(f"STDERR:\n{err}")

    if exit_status != 0:
        if "already on" in err.lower() or "already at" in err.lower() or "detached head" in err.lower():
            logger.warning(f"Команда завершилась с предупреждением (exit status {exit_status}): {full_command}\n{err}")
        elif "no such service" in err.lower() or "no such container" in err.lower() or "cannot find" in err.lower():
            logger.warning(f"Команда завершилась с предупреждением (exit status {exit_status}): {full_command}\n{err}")
        else:
            logger.error(f"Команда завершилась с ошибкой (exit status {exit_status}): {full_command}\n{err}")
            raise Exception(f"{error_message}: {err}")
    elif err:
        logger.warning(f"Команда завершилась успешно, но с предупреждениями в STDERR: {full_command}\n{err}")
    
    return out, err

def _get_docker_ps_raw(ssh_client: paramiko.SSHClient, repo_name: str) -> str:
    """
    Получает отформатированный вывод `docker ps` для репозитория.
    """
    # Используем --format "table..." для вывода таблицы с заголовком и нужными полями.
    # --filter используется для выбора контейнеров, связанных с репозиторием.
    command = "docker ps --format 'table {{.Image}}\t{{.Status}}\t{{.Ports}}'"
    stdin, stdout, stderr = ssh_client.exec_command(command)
    
    # Читаем весь вывод
    output = stdout.read().decode()
    error_output = stderr.read().decode()
    
    if output:
        logger.info(f"STDOUT от 'docker ps':\n{output}")
    if error_output:
        logger.warning(f"STDERR от 'docker ps':\n{error_output}")
    
    if stdout.channel.recv_exit_status() != 0:
        logger.error(f"Команда 'docker ps' завершилась с ошибкой. Вывод: {error_output}")
        return f"Ошибка при получении статуса Docker: {error_output}"

    # Если вывода больше одной строки (заголовок + данные), значит, контейнеры найдены.
    if len(output.strip().splitlines()) > 1:
        return output
    else:
        # Если вывода нет или только заголовок, значит, контейнеры не найдены.
        return "Нет запущенных контейнеров Docker, связанных с этим репозиторием."
def get_commits_from_git_repo(repo_url: str, branch: str = "main", ssh_key_path: Optional[str] = None) -> List[CommitInfo]:
    """
    Клонирует репозиторий в временную директорию и получает последние 10 коммитов
    с помощью git log.
    """
    found_commits = []
    temp_dir = None
    try:
        logger.info(f"Получение коммитов из репозитория {repo_url} (ветка: {branch}) через git clone.")
        temp_dir = tempfile.mkdtemp()

        ssh_port_match = re.search(r':(\d+)/', repo_url)
        port_option = f"-p {ssh_port_match.group(1)}" if ssh_port_match else ""
        
        git_ssh_command_str = f"ssh -i {ssh_key_path} -o StrictHostKeyChecking=no {port_option}" if ssh_key_path else None

        env = os.environ.copy()
        if git_ssh_command_str:
            env["GIT_SSH_COMMAND"] = git_ssh_command_str
        
        clone_command = ["git", "clone", "--depth", "10", "--branch", branch, repo_url, temp_dir]
        
        result = subprocess.run(clone_command, capture_output=True, text=True, check=True, env=env)
        logger.info(f"Репозиторий {repo_url} успешно клонирован в {temp_dir}.")

        log_command = ["git", "log", "--pretty=format:%H|%s", "-10"]
        log_result = subprocess.run(log_command, cwd=temp_dir, capture_output=True, text=True, check=True)
        
        commits_output = log_result.stdout.strip().split('\n')
        
        for line in commits_output:
            if line:
                try:
                    commit_hash, commit_message = line.split('|', 1)
                    found_commits.append(CommitInfo(hash=commit_hash.strip(), message=commit_message.strip()))
                except ValueError:
                    logger.warning(f"Не удалось распарсить строку коммита: {line}")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка выполнения git-команды: {e.stderr}")
        found_commits.append(CommitInfo(hash="error", message=f"Ошибка Git: {e.stderr.strip()}"))
    except Exception as e:
        logger.error(f"Неизвестная ошибка при получении коммитов: {e}")
        found_commits.append(CommitInfo(hash="error", message=f"Неизвестная ошибка: {e}"))
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir)
            logger.info(f"Временная директория {temp_dir} удалена.")
            
    return found_commits

@app.get("/repos", response_model=List[Dict])
async def get_repositories():
    """
    Возвращает список доступных репозиториев с их последними 10 коммитами.
    """
    repo_list = []
    repositories_from_config = _config.get("repositories", [])
    logger.info(f"Найдено {len(repositories_from_config)} репозиториев в конфигурации для обработки.")

    for repo_config in repositories_from_config:
        repo_name = repo_config["name"]
        git_url = repo_config["git_url"]
        branch = repo_config.get("branch", "main")
        repo_ssh_key = repo_config.get("repo_ssh_key")
        
        commits = get_commits_from_git_repo(git_url, branch, repo_ssh_key)
        
        repo_list.append({
            "name": repo_name,
            "git_url": git_url,
            "branch": branch,
            "server_info": {
                "ip": repo_config["server"]["ip"],
                "user": repo_config["server"]["user"],
                "deploy_path": repo_config["server"]["deploy_path"]
            },
            "commits": [commit.model_dump() for commit in commits]
        })
    logger.info(f"Сформирован список из {len(repo_list)} репозиториев для фронтенда.")
    return repo_list

@app.post("/deploy/{repo_name}")
async def deploy_repo(repo_name: str, request: DeployRequest):
    """
    Деплоит выбранный коммит на удаленный сервер: клонирует/обновляет репозиторий,
    переключается на коммит, собирает и запускает docker-compose.
    """
    logger.info(f"Получен запрос на деплой '{repo_name}' на коммит '{request.commit_hash}'.")
    repo = next((r for r in _config.get("repositories", []) if r["name"] == repo_name), None)
    if not repo:
        logger.error(f"Репозиторий '{repo_name}' не найден в конфигурации.")
        raise HTTPException(status_code=404, detail="Репозиторий не найден в конфигурации")

    server_ip = repo["server"]["ip"]
    server_user = repo["server"]["user"]
    ssh_key_path = repo["server"]["ssh_key"]
    deploy_path = repo["server"]["deploy_path"]
    commit_hash = request.commit_hash
    git_url = repo["git_url"]
    repo_ssh_key = repo["repo_ssh_key"]
    
    if not all([server_ip, server_user, ssh_key_path, deploy_path, commit_hash]):
        logger.error(f"Недостающие данные конфигурации для деплоя репозитория '{repo_name}'.")
        raise HTTPException(status_code=500, detail="Недостающие данные конфигурации для сервера или коммита")

    ssh = None
    sftp = None
    remote_repo_key_path = None
    output_log = []
    try:
        logger.info(f"Подключение к {server_user}@{server_ip} с ключом {ssh_key_path}...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server_ip,
            username=server_user,
            key_filename=ssh_key_path,
            timeout=30
        )
        output_log.append(f"Успешно подключено к {server_ip}")
        logger.info(f"Подключение к {server_ip} установлено.")
        
        if repo_ssh_key:
            sftp = paramiko.SFTPClient.from_transport(ssh.get_transport())
            key_filename = os.path.basename(repo_ssh_key)
            remote_repo_key_path = f"/tmp/{key_filename}"
            sftp.put(repo_ssh_key, remote_repo_key_path)
            _execute_remote_command(ssh, f"chmod 600 {remote_repo_key_path}", "Ошибка установки прав на SSH-ключ", output_log)
            logger.info(f"Ключ репозитория успешно скопирован в {remote_repo_key_path} на удаленном сервере.")
        
        ssh_port_match = re.search(r':(\d+)/', git_url)
        port_option = f"-p {ssh_port_match.group(1)}" if ssh_port_match else ""

        git_ssh_command_str = f"export GIT_SSH_COMMAND=\"ssh -i {remote_repo_key_path} -o StrictHostKeyChecking=no {port_option}\"" if remote_repo_key_path else ""
        
        _execute_remote_command(ssh, f"mkdir -p {deploy_path}", "Ошибка при создании директории", output_log, prepend_commands=git_ssh_command_str)
        output_log.append(f"Директория {deploy_path} проверена/создана.")

        repo_status_cmd = f'[ -d {deploy_path}/.git ] && echo "exists" || echo "not_exists"'
        repo_status_out, _ = _execute_remote_command(ssh, repo_status_cmd, "Ошибка проверки статуса репозитория", output_log, prepend_commands=git_ssh_command_str)
        repo_status = repo_status_out.strip()
        logger.info(f"Статус репозитория в {deploy_path} на {server_ip}: {repo_status}")

        if repo_status == "not_exists":
            _execute_remote_command(ssh, f"cd {deploy_path} && git clone {git_url} .", "Ошибка клонирования", output_log, prepend_commands=git_ssh_command_str)
            output_log.append(f"Клонирование репозитория {git_url} завершено.")
        else:
            _execute_remote_command(ssh, f"cd {deploy_path} && git fetch --all --prune", "Ошибка обновления репозитория", output_log, prepend_commands=git_ssh_command_str)
            output_log.append("Обновление репозитория завершено.")
        
        _execute_remote_command(ssh, f"cd {deploy_path} && git checkout -f {commit_hash}", "Ошибка переключения на коммит", output_log, prepend_commands=git_ssh_command_str)
        output_log.append(f"Переключение на коммит {commit_hash} завершено.")

        docker_commands = [
            f"cd {deploy_path}",
            f"docker-compose down",
            f"docker-compose build",
            f"docker-compose up -d"
        ]
        _execute_remote_command(ssh, " && ".join(docker_commands), "Ошибка Docker Compose", output_log)
        output_log.append("Docker Compose действия (down, build, up -d) завершены.")

        logger.info(f"Деплой '{repo_name}' на коммит '{commit_hash}' успешно завершен.")
        return {"status": "success", "output": "\n".join(output_log)}

    except paramiko.AuthenticationException as e:
        logger.error(f"Ошибка аутентификации при подключении к {server_ip}: {e}")
        raise HTTPException(status_code=401, detail=f"Ошибка аутентификации: Проверьте SSH-ключ и права доступа. {e}")
    except paramiko.SSHException as e:
        logger.error(f"Ошибка SSH при подключении/выполнении команд на {server_ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка SSH: Не удалось подключиться или выполнить команды. {e}")
    except Exception as e:
        logger.error(f"Неизвестная ошибка деплоя для '{repo_name}': {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка деплоя: {e}")
    finally:
        if ssh:
            if sftp and remote_repo_key_path:
                try:
                    sftp.remove(remote_repo_key_path)
                    logger.info(f"Временный ключ {remote_repo_key_path} успешно удален с сервера.")
                except Exception as e:
                    logger.warning(f"Не удалось удалить временный ключ с сервера: {e}")
                finally:
                    sftp.close()
            ssh.close()
            logger.info(f"SSH-соединение с {server_ip} закрыто.")

@app.get("/status/{repo_name}")
async def get_repo_status(repo_name: str):
    """
    Получает необработанный вывод `docker ps` для указанного репозитория.
    """
    logger.info(f"Получен запрос на получение статуса для '{repo_name}'.")
    repo = next((r for r in _config.get("repositories", []) if r["name"] == repo_name), None)
    if not repo:
        logger.error(f"Репозиторий '{repo_name}' не найден в конфигурации.")
        raise HTTPException(status_code=404, detail="Репозиторий не найден в конфигурации")

    server_ip = repo["server"]["ip"]
    server_user = repo["server"]["user"]
    ssh_key_path = repo["server"]["ssh_key"]
    deploy_path = repo["server"]["deploy_path"]

    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server_ip,
            username=server_user,
            key_filename=ssh_key_path,
            timeout=30
        )
        logger.info(f"Подключение к {server_ip} установлено.")

        # Проверяем, существует ли репозиторий на сервере
        repo_status_cmd = f'[ -d {deploy_path}/.git ] && echo "exists" || echo "not_exists"'
        stdin, stdout, stderr = ssh.exec_command(repo_status_cmd)
        repo_exists = stdout.read().decode().strip() == "exists"
        
        if not repo_exists:
            return {"status": "not_deployed", "output": "Сервис еще не установлен на сервере."}

        # Получаем необработанный вывод docker ps
        raw_docker_output = _get_docker_ps_raw(ssh, repo_name)
        
        return {"status": "deployed", "output": raw_docker_output}

    except paramiko.AuthenticationException as e:
        logger.error(f"Ошибка аутентификации при получении статуса с {server_ip}: {e}")
        raise HTTPException(status_code=401, detail=f"Ошибка аутентификации: {e}")
    except paramiko.SSHException as e:
        logger.error(f"Ошибка SSH при получении статуса с {server_ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка SSH: {e}")
    except Exception as e:
        logger.error(f"Неизвестная ошибка при получении статуса для '{repo_name}': {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка: {e}")
    finally:
        if ssh:
            ssh.close()
            logger.info(f"SSH-соединение с {server_ip} закрыто.")

@app.post("/run/{repo_name}")
async def run_microservice(repo_name: str):
    """
    Запускает (или перезапускает) микросервис, используя docker-compose up -d.
    """
    logger.info(f"Получен запрос на запуск '{repo_name}'.")
    repo = next((r for r in _config.get("repositories", []) if r["name"] == repo_name), None)
    if not repo:
        logger.error(f"Репозиторий '{repo_name}' не найден в конфигурации.")
        raise HTTPException(status_code=404, detail="Репозиторий не найден в конфигурации")

    server_ip = repo["server"]["ip"]
    server_user = repo["server"]["user"]
    ssh_key_path = repo["server"]["ssh_key"]
    deploy_path = repo["server"]["deploy_path"]
    docker_compose_file = repo.get("docker_compose_file", "docker-compose.yml")

    if not all([server_ip, server_user, ssh_key_path, deploy_path]):
        logger.error(f"Недостающие данные конфигурации для запуска репозитория '{repo_name}'.")
        raise HTTPException(status_code=500, detail="Недостающие данные конфигурации для сервера")

    ssh = None
    output_log = []
    try:
        logger.info(f"Подключение к {server_user}@{server_ip} для запуска сервиса...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server_ip,
            username=server_user,
            key_filename=ssh_key_path,
            timeout=30
        )
        output_log.append(f"Успешно подключено к {server_ip}")
        logger.info(f"Подключение к {server_ip} установлено.")

        cmd_check_repo_exists = f'[ -d {deploy_path}/.git ]'
        _, err = _execute_remote_command(ssh, cmd_check_repo_exists, "Ошибка проверки наличия репозитория", output_log)
        if err:
             raise HTTPException(status_code=400, detail="Репозиторий не найден на сервере. Сначала выполните 'Установить версию'.")

        docker_commands = [
            f"cd {deploy_path}",
            f"docker-compose up -d"
        ]
        _execute_remote_command(ssh, " && ".join(docker_commands), "Ошибка Docker Compose при запуске", output_log)
        output_log.append("Docker Compose up -d завершен.")

        logger.info(f"Микросервис '{repo_name}' успешно запущен/перезапущен.")
        return {"status": "success", "output": "\n".join(output_log)}

    except paramiko.AuthenticationException as e:
        logger.error(f"Ошибка аутентификации при запуске {server_ip}: {e}")
        raise HTTPException(status_code=401, detail=f"Ошибка аутентификации: Проверьте SSH-ключ и права доступа. {e}")
    except paramiko.SSHException as e:
        logger.error(f"Ошибка SSH при запуске/выполнении команд на {server_ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка SSH: Не удалось подключиться или выполнить команды. {e}")
    except Exception as e:
        logger.error(f"Неизвестная ошибка при запуске для '{repo_name}': {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка запуска: {e}")
    finally:
        if ssh:
            ssh.close()
            logger.info(f"SSH-соединение с {server_ip} закрыто.")

@app.post("/stop/{repo_name}")
async def stop_microservice(repo_name: str):
    """
    Останавливает микросервис, используя docker-compose down.
    """
    logger.info(f"Получен запрос на остановку '{repo_name}'.")
    repo = next((r for r in _config.get("repositories", []) if r["name"] == repo_name), None)
    if not repo:
        logger.error(f"Репозиторий '{repo_name}' не найден в конфигурации.")
        raise HTTPException(status_code=404, detail="Репозиторий не найден в конфигурации")

    server_ip = repo["server"]["ip"]
    server_user = repo["server"]["user"]
    ssh_key_path = repo["server"]["ssh_key"]
    deploy_path = repo["server"]["deploy_path"]
    docker_compose_file = repo.get("docker_compose_file", "docker-compose.yml")

    if not all([server_ip, server_user, ssh_key_path, deploy_path]):
        logger.error(f"Недостающие данные конфигурации для остановки репозитория '{repo_name}'.")
        raise HTTPException(status_code=500, detail="Недостающие данные конфигурации для сервера")

    ssh = None
    output_log = []
    try:
        logger.info(f"Подключение к {server_user}@{server_ip} для остановки сервиса...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=server_ip,
            username=server_user,
            key_filename=ssh_key_path,
            timeout=30
        )
        output_log.append(f"Успешно подключено к {server_ip}")
        logger.info(f"Подключение к {server_ip} установлено.")

        cmd_check_repo_exists = f'[ -d {deploy_path}/.git ]'
        _, err = _execute_remote_command(ssh, cmd_check_repo_exists, "Ошибка проверки наличия репозитория", output_log)
        if err:
            raise HTTPException(status_code=400, detail="Репозиторий не найден на сервере. Невозможно остановить сервис.")

        docker_commands = [
            f"cd {deploy_path}",
            f"docker-compose down"
        ]
        _execute_remote_command(ssh, " && ".join(docker_commands), "Ошибка Docker Compose при остановке", output_log)
        output_log.append("Docker Compose down завершен.")

        logger.info(f"Микросервис '{repo_name}' успешно остановлен.")
        return {"status": "success", "output": "\n".join(output_log)}

    except paramiko.AuthenticationException as e:
        logger.error(f"Ошибка аутентификации при остановке {server_ip}: {e}")
        raise HTTPException(status_code=401, detail=f"Ошибка аутентификации при остановке: {e}")
    except paramiko.SSHException as e:
        logger.error(f"Ошибка SSH при остановке/выполнении команд на {server_ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка SSH при остановке: {e}")
    except Exception as e:
        logger.error(f"Неизвестная ошибка при остановке для '{repo_name}': {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка остановки: {e}")
    finally:
        if ssh:
            ssh.close()
            logger.info(f"SSH-соединение с {server_ip} закрыто.")
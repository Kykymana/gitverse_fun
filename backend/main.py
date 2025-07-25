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

def get_commits_from_gitverse(repo_url: str, branch: str = "master") -> List[CommitInfo]:
    """
    Получает последние 10 коммитов (хэш и сообщение) из GitVerse для заданного репозитория и ветки.
    Адаптировано из предоставленного пользователем кода.
    """
    commits_url = f"{repo_url}/commits/branch/{branch}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    }
    
    found_commits = []
    try:
        logger.info(f"Запрос коммитов для {repo_url} (ветка: {branch}) по URL: {commits_url}")
        response = requests.get(commits_url, headers=headers, timeout=15)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        
        for link in soup.find_all("a", href=lambda x: x and "/commit/" in x):
            if len(found_commits) >= 10:
                break
            
            commit_url = f"https://gitverse.ru{link['href']}" if not link['href'].startswith('http') else link['href']
            commit_message = link.text.strip()
            
            match = re.search(r'/commit/([0-9a-fA-F]+)', commit_url)
            commit_hash = match.group(1) if match else None
            
            if commit_hash and commit_message:
                found_commits.append(CommitInfo(hash=commit_hash, message=commit_message))
            else:
                logger.warning(f"Не удалось извлечь хэш или сообщение из ссылки: {link}")
                
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка сети/HTTP при получении коммитов для {repo_url}: {e}")
        found_commits.append(CommitInfo(hash="error", message=f"Ошибка сети/HTTP: {e}"))
    except Exception as e:
        logger.error(f"Общая ошибка при парсинге коммитов для {repo_url}: {e}")
        found_commits.append(CommitInfo(hash="error", message=f"Ошибка парсинга: {e}"))
            
    logger.info(f"Возвращено {len(found_commits)} коммитов для {repo_url}.")
    return found_commits[:10]

def _execute_remote_command(ssh_client: paramiko.SSHClient, command: str, error_message: str, output_log: List[str]) -> Tuple[str, str]:
    """
    Выполняет команду на удаленном сервере через SSH и обрабатывает вывод.
    Возвращает (stdout, stderr). Вызывает исключение при ошибке.
    """
    logger.info(f"Выполнение команды: {command}")
    stdin, stdout, stderr = ssh_client.exec_command(command)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    exit_status = stdout.channel.recv_exit_status() # Получаем код выхода команды

    output_log.append(f"Команда: {command}")
    if out:
        output_log.append(f"STDOUT:\n{out}")
    if err:
        output_log.append(f"STDERR:\n{err}")

    # Проверяем код выхода и наличие явных ошибок в stderr
    if exit_status != 0:
        # Игнорируем некоторые "ошибки", которые на самом деле не являются критичными
        if "already on" in err.lower() or "already at" in err.lower() or "detached head" in err.lower():
            logger.warning(f"Команда завершилась с предупреждением (exit status {exit_status}): {command}\n{err}")
        elif "no such service" in err.lower() or "no such container" in err.lower() or "cannot find" in err.lower():
            logger.warning(f"Команда завершилась с предупреждением (exit status {exit_status}): {command}\n{err}")
        else:
            logger.error(f"Команда завершилась с ошибкой (exit status {exit_status}): {command}\n{err}")
            raise Exception(f"{error_message}: {err}")
    elif err: # Если exit_status 0, но есть что-то в stderr (могут быть предупреждения)
        logger.warning(f"Команда завершилась успешно, но с предупреждениями в STDERR: {command}\n{err}")
    
    return out, err


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
        
        commits = get_commits_from_gitverse(git_url, branch)
        
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
    docker_compose_file = repo.get("docker_compose_file", "docker-compose.yml")

    if not all([server_ip, server_user, ssh_key_path, deploy_path, commit_hash]):
        logger.error(f"Недостающие данные конфигурации для деплоя репозитория '{repo_name}'.")
        raise HTTPException(status_code=500, detail="Недостающие данные конфигурации для сервера или коммита")

    ssh = None
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

        _execute_remote_command(ssh, f"mkdir -p {deploy_path}", "Ошибка при создании директории", output_log)
        output_log.append(f"Директория {deploy_path} проверена/создана.")

        repo_status_cmd = f'[ -d {deploy_path}/.git ] && echo "exists" || echo "not_exists"'
        repo_status_out, _ = _execute_remote_command(ssh, repo_status_cmd, "Ошибка проверки статуса репозитория", output_log)
        repo_status = repo_status_out.strip()
        logger.info(f"Статус репозитория в {deploy_path} на {server_ip}: {repo_status}")

        if repo_status == "not_exists":
            _execute_remote_command(ssh, f"cd {deploy_path} && git clone {repo['git_url']} .", "Ошибка клонирования", output_log)
            output_log.append(f"Клонирование репозитория {repo['git_url']} завершено.")
        else:
            _execute_remote_command(ssh, f"cd {deploy_path} && git fetch --all && git reset --hard origin/{repo.get('branch', 'main')}", "Ошибка обновления репозитория", output_log)
            output_log.append("Обновление репозитория завершено.")
        
        _execute_remote_command(ssh, f"cd {deploy_path} && git checkout {commit_hash}", "Ошибка переключения на коммит", output_log)
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

        # Проверяем наличие репозитория перед попыткой запуска docker-compose
        cmd_check_repo_exists = f'[ -d {deploy_path}/.git ]'
        _, err = _execute_remote_command(ssh, cmd_check_repo_exists, "Ошибка проверки наличия репозитория", output_log)
        # Если команда проверки репозитория вернула ошибку (например, директории нет), то это проблема
        if err: # Если err не пустой, значит что-то пошло не так с проверкой, даже если exit_status был 0
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
        raise HTTPException(status_code=401, detail=f"Ошибка аутентификации: Проверьте SSH-ключ и права доступа. {e}")
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
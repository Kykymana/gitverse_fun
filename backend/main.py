import json
import logging
import re
import requests
import paramiko
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional

# --- Настройка логирования ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

# --- Настройка CORS Middleware ---
# Разрешаем запросы с фронтенда, работающего на localhost:8888 (через Docker Compose)
origins = [
    "http://localhost:8888",
    "http://127.0.0.1:8888",
    # Если вы будете деплоить фронтенд на другой домен/IP, добавьте его сюда
    # "http://your-frontend-domain.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Разрешаем все HTTP методы
    allow_headers=["*"],  # Разрешаем все заголовки
)

# --- Глобальная переменная для хранения конфигурации ---
_config: Dict = {}

# --- Модели данных для FastAPI ---
class CommitInfo(BaseModel):
    hash: str
    message: str

class DeployRequest(BaseModel):
    commit_hash: str

# --- Функция загрузки конфигурации ---
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

# Загружаем конфигурацию при старте FastAPI приложения
@app.on_event("startup")
async def startup_event():
    load_config_on_startup()


# --- Адаптированная функция для получения коммитов из GitVerse ---
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
        response.raise_for_status()  # Вызывает исключение для HTTP ошибок (4xx, 5xx)
        
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Ищем все ссылки, которые содержат и текст (название коммита), и ведут на коммит
        for link in soup.find_all("a", href=lambda x: x and "/commit/" in x):
            if len(found_commits) >= 10:
                break
            
            commit_url = f"https://gitverse.ru{link['href']}" if not link['href'].startswith('http') else link['href']
            commit_message = link.text.strip()
            
            # Извлекаем хэш из URL коммита
            match = re.search(r'/commit/([0-9a-fA-F]+)', commit_url)
            commit_hash = match.group(1) if match else None
            
            if commit_hash and commit_message:  # Если есть текст и хэш
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
    return found_commits[:10] # Гарантируем не более 10


# --- API Эндпоинты ---
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
            "commits": [commit.model_dump() for commit in commits] # Конвертируем Pydantic модель в dict
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
            timeout=30 # Таймаут подключения SSH
        )
        output_log.append(f"Успешно подключено к {server_ip}")
        logger.info(f"Подключение к {server_ip} установлено.")

        # 1. Проверка и создание директории
        cmd_mkdir = f"mkdir -p {deploy_path}"
        logger.info(f"Выполнение: {cmd_mkdir}")
        stdin, stdout, stderr = ssh.exec_command(cmd_mkdir)
        err = stderr.read().decode().strip()
        if err:
            output_log.append(f"Внимание: Ошибка при создании директории (возможно, уже существует): {err}")
            logger.warning(f"Ошибка при создании директории {deploy_path} на {server_ip}: {err}")
        else:
            output_log.append(f"Директория {deploy_path} проверена/создана.")

        # 2. Клонирование или обновление репозитория
        cmd_check_repo = f'[ -d {deploy_path}/.git ] && echo "exists" || echo "not_exists"'
        stdin, stdout, stderr = ssh.exec_command(cmd_check_repo)
        repo_status = stdout.read().decode().strip()
        logger.info(f"Статус репозитория в {deploy_path} на {server_ip}: {repo_status}")

        if repo_status == "not_exists":
            cmd_git_clone = f"cd {deploy_path} && git clone {repo['git_url']} ."
            logger.info(f"Клонирование репозитория '{repo_name}' из {repo['git_url']} в {deploy_path}...")
            output_log.append(f"Клонирование репозитория {repo['git_url']}...")
            stdin, stdout, stderr = ssh.exec_command(cmd_git_clone)
            out = stdout.read().decode()
            err = stderr.read().decode()
            output_log.append(out)
            if err and "error" in err.lower():
                output_log.append(f"Ошибка клонирования: {err}")
                raise Exception(f"Ошибка клонирования: {err}")
            logger.info("Клонирование завершено.")
        else:
            cmd_git_pull = f"cd {deploy_path} && git fetch --all && git reset --hard origin/{repo.get('branch', 'main')}"
            logger.info(f"Обновление репозитория '{repo_name}' в {deploy_path}...")
            output_log.append("Обновление репозитория...")
            stdin, stdout, stderr = ssh.exec_command(cmd_git_pull)
            out = stdout.read().decode()
            err = stderr.read().decode()
            output_log.append(out)
            if err and "error" in err.lower():
                output_log.append(f"Ошибка обновления: {err}")
                raise Exception(f"Ошибка обновления: {err}")
            logger.info("Обновление завершено.")
        
        # 3. Переключение на коммит
        cmd_git_checkout = f"cd {deploy_path} && git checkout {commit_hash}"
        logger.info(f"Переключение '{repo_name}' на коммит '{commit_hash}'...")
        output_log.append(f"Переключение на коммит {commit_hash}...")
        stdin, stdout, stderr = ssh.exec_command(cmd_git_checkout)
        out = stdout.read().decode()
        err = stderr.read().decode()
        output_log.append(out)
        if err and "error" in err.lower() and "already on" not in err.lower() and "already at" not in err.lower():
            output_log.append(f"Ошибка переключения на коммит: {err}")
            raise Exception(f"Ошибка переключения на коммит: {err}")
        logger.info(f"Переключение на коммит '{commit_hash}' завершено.")

        # 4. Docker Compose действия: остановка, сборка, запуск
        docker_commands = [
            f"cd {deploy_path}",
            f"docker-compose down", # Останавливаем и удаляем неиспользуемые контейнеры
            f"docker-compose build", # Пересобираем образы
            f"docker-compose up -d" # Запускаем в фоновом режиме
        ]
        cmd_docker_compose = " && ".join(docker_commands)
        logger.info(f"Выполнение Docker Compose команд для '{repo_name}' в {deploy_path}...")
        output_log.append("Выполнение Docker Compose команд (down, build, up -d)...")
        stdin, stdout, stderr = ssh.exec_command(cmd_docker_compose)
        out = stdout.read().decode()
        err = stderr.read().decode()
        output_log.append(out)
        if err and "error" in err.lower():
            output_log.append(f"Ошибка Docker Compose: {err}")
            raise Exception(f"Ошибка Docker Compose: {err}")
        logger.info(f"Docker Compose действия для '{repo_name}' завершены.")

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
        stdin, stdout, stderr = ssh.exec_command(cmd_check_repo_exists)
        if stdout.channel.recv_exit_status() != 0: # Если команда вернула ошибку (директории нет)
            output_log.append(f"Ошибка: Репозиторий не найден в {deploy_path}. Сначала выполните 'Установить версию'.")
            logger.error(f"Репозиторий не найден в {deploy_path} для '{repo_name}'.")
            raise HTTPException(status_code=400, detail="Репозиторий не найден на сервере. Сначала выполните 'Установить версию'.")

        # Команды для запуска/перезапуска Docker Compose
        docker_commands = [
            f"cd {deploy_path}",
            f"docker-compose up -d" # Просто запускаем/перезапускаем
        ]
        cmd_docker_compose = " && ".join(docker_commands)
        logger.info(f"Выполнение Docker Compose up -d для '{repo_name}' в {deploy_path}...")
        output_log.append("Выполнение Docker Compose up -d...")
        stdin, stdout, stderr = ssh.exec_command(cmd_docker_compose)
        out = stdout.read().decode()
        err = stderr.read().decode()
        output_log.append(out)
        if err and "error" in err.lower():
            output_log.append(f"Ошибка Docker Compose: {err}")
            raise Exception(f"Ошибка Docker Compose: {err}")
        logger.info(f"Docker Compose up -d для '{repo_name}' завершен.")

        logger.info(f"Микросервис '{repo_name}' успешно запущен/перезапущен.")
        return {"status": "success", "output": "\n".join(output_log)}

    except paramiko.AuthenticationException as e:
        logger.error(f"Ошибка аутентификации при запуске {server_ip}: {e}")
        raise HTTPException(status_code=401, detail=f"Ошибка аутентификации: Проверьте SSH-ключ и права доступа. {e}")
    except paramiko.SSHException as e:
        logger.error(f"Ошибка SSH при запуске/выполнении команд на {server_ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка SSH при запуске: {e}")
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

        # Проверяем наличие репозитория перед попыткой остановки docker-compose
        cmd_check_repo_exists = f'[ -d {deploy_path}/.git ]'
        stdin, stdout, stderr = ssh.exec_command(cmd_check_repo_exists)
        if stdout.channel.recv_exit_status() != 0: # Если команда вернула ошибку (директории нет)
            output_log.append(f"Ошибка: Репозиторий не найден в {deploy_path}. Невозможно остановить сервис.")
            logger.error(f"Репозиторий не найден в {deploy_path} для '{repo_name}'.")
            raise HTTPException(status_code=400, detail="Репозиторий не найден на сервере. Невозможно остановить сервис.")

        # Команды для остановки Docker Compose
        docker_commands = [
            f"cd {deploy_path}",
            f"docker-compose down"
        ]
        cmd_docker_compose = " && ".join(docker_commands)
        logger.info(f"Выполнение Docker Compose down для '{repo_name}' в {deploy_path}...")
        output_log.append("Выполнение Docker Compose down...")
        stdin, stdout, stderr = ssh.exec_command(cmd_docker_compose)
        out = stdout.read().decode()
        err = stderr.read().decode()
        output_log.append(out)

        # Обрабатываем ошибки остановки: если сервис не запущен, это не всегда ошибка
        if err and "error" in err.lower():
            if "no such service" in err.lower() or "no such container" in err.lower() or "cannot find" in err.lower():
                output_log.append(f"Предупреждение: Сервис '{repo_name}' не был запущен или не найден. {err}")
                logger.warning(f"Сервис '{repo_name}' не был запущен для остановки: {err}")
            else:
                output_log.append(f"Ошибка Docker Compose при остановке: {err}")
                raise Exception(f"Ошибка Docker Compose при остановке: {err}")
        else:
            logger.info(f"Docker Compose down для '{repo_name}' завершен.")

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
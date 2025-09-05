import json
import logging
import re
import subprocess
import os
import shutil
from contextlib import asynccontextmanager
from typing import List, Dict, Optional, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Глобальные переменные и константы
_config: Dict = {}
CONFIG_PATH = os.environ.get("CONFIG_PATH", "config.json")
LOCAL_REPOS_PATH = os.path.join(os.getcwd(), "local_repos")
CMD_TIMEOUT = 180

# -------------------------------------------------------------------
# ИСПРАВЛЕННЫЙ БЛОК ИНИЦИАЛИЗАЦИИ ПРИЛОЖЕНИЯ
# -------------------------------------------------------------------

def save_config():
    """Сохранение текущей конфигурации в JSON файл."""
    global _config
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(_config, f, indent=4)
        logger.info(f"Конфигурация успешно сохранена в {CONFIG_PATH}.")
    except Exception as e:
        logger.error(f"Ошибка при сохранении {CONFIG_PATH}: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка при сохранении конфигурации: {e}")

def load_config_on_startup():
    """Загрузка конфигурации из JSON файла при старте приложения."""
    global _config
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as f:
                _config = json.load(f)
            logger.info("Конфигурация успешно загружена.")
        else:
            logger.warning(f"Файл {CONFIG_PATH} не найден. Будет создан пустой конфигурационный файл.")
            _config = {"repositories": []}
            save_config()
        if not _config.get("repositories"):
            logger.warning("В config.json отсутствует или пуста секция 'repositories'.")
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка: Неверный формат JSON в {CONFIG_PATH}: {e}. Проверьте синтаксис файла.")
        _config = {"repositories": []}
    except Exception as e:
        logger.error(f"Неизвестная ошибка при загрузке {CONFIG_PATH}: {e}")
        _config = {"repositories": []}

# Сначала определяем функцию lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    load_config_on_startup()
    yield

# Затем создаем ЕДИНСТВЕННЫЙ экземпляр FastAPI, передавая ему lifespan
app = FastAPI(lifespan=lifespan)

# И уже к этому экземпляру применяем CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В production лучше указать конкретный домен фронтенда
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# КОНЕЦ ИСПРАВЛЕННОГО БЛОКА. ДАЛЕЕ КОД БЕЗ ИЗМЕНЕНИЙ.
# -------------------------------------------------------------------

# Pydantic модели
class CommitInfo(BaseModel):
    hash: str
    message: str

class DeployRequest(BaseModel):
    commit_hash: str

class ServerConfig(BaseModel):
    ip: str
    user: str
    deploy_path: str
    ssh_key: Optional[str] = None

class RepositoryConfig(BaseModel):
    name: str
    git_url: str
    branch: str = "main"
    server: ServerConfig
    docker_compose_file: str = "docker-compose.yml"
    current_deployed_commit: Optional[str] = None
    previous_deployed_commit: Optional[str] = None

# Вспомогательные функции
def _run_local_shell_command(command: str, cwd: Optional[str] = None) -> Tuple[str, str]:
    """
    Выполняет локальную команду shell и возвращает (stdout, stderr).
    """
    try:
        logger.info(f"Выполнение локальной команды: {command}")
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT,
            cwd=cwd
        )
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка локальной команды: {e.cmd}")
        logger.error(f"STDOUT: {e.stdout}")
        logger.error(f"STDERR: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"Ошибка локальной команды: {e.stderr.strip()}")
    except subprocess.TimeoutExpired as e:
        logger.error(f"Таймаут локальной команды: {e.cmd}")
        raise HTTPException(status_code=500, detail=f"Таймаут локальной команды: {e.cmd}")
        
def _run_remote_shell_command(ssh_command: str) -> Tuple[str, str]:
    """
    Выполняет удаленную команду shell через SSH и возвращает (stdout, stderr).
    """
    try:
        logger.info(f"Выполнение удаленной команды: {ssh_command}")
        result = subprocess.run(
            ssh_command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT
        )
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка удаленной команды: {e.cmd}")
        logger.error(f"STDOUT: {e.stdout}")
        logger.error(f"STDERR: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"Ошибка удаленной команды: {e.stderr.strip()}")
    except subprocess.TimeoutExpired as e:
        logger.error(f"Таймаут удаленной команды: {e.cmd}")
        raise HTTPException(status_code=500, detail=f"Таймаут удаленной команды: {e.cmd}")

def get_commits_from_git_repo(repo_url: str, branch: str = "main") -> List[CommitInfo]:
    """
    Клонирует или обновляет репозиторий локально и получает последние 10 коммитов.
    """
    found_commits = []
    repo_name = repo_url.split('/')[-1].replace('.git', '')
    local_path = os.path.join(LOCAL_REPOS_PATH, repo_name)

    if not os.path.exists(LOCAL_REPOS_PATH):
        os.makedirs(LOCAL_REPOS_PATH)
        logger.info(f"Создана локальная папка для репозиториев: {LOCAL_REPOS_PATH}")

    if not os.path.exists(local_path):
        _run_local_shell_command(f"git clone --branch {branch} {repo_url} {local_path}")
    else:
        _run_local_shell_command(f"git checkout {branch}", cwd=local_path)
        _run_local_shell_command("git pull", cwd=local_path)
    
    log_command = f"git log --pretty=format:%H|%an|%s --max-count=10"
    commits_output, _ = _run_local_shell_command(log_command, cwd=local_path)

    for line in commits_output.splitlines():
        if line:
            try:
                commit_hash, author, commit_message = line.split('|', 2)
                found_commits.append(CommitInfo(hash=commit_hash.strip(), message=f"({author.strip()}) {commit_message.strip()}"))
            except ValueError:
                logger.warning(f"Не удалось распарсить строку коммита: {line}")

    return found_commits

def _perform_deploy_action(repo: Dict, commit_hash: str, action_name: str):
    """
    Вспомогательная функция для выполнения команд деплоя.
    """
    repo_name = repo["name"]
    server_ip = repo["server"]["ip"]
    server_user = repo["server"]["user"]
    ssh_key_path = repo["server"]["ssh_key"]
    deploy_path = repo["server"]["deploy_path"]
    docker_compose_file = repo.get("docker_compose_file", "docker-compose.yml")
    local_path = os.path.join(LOCAL_REPOS_PATH, repo_name)
    
    if not os.path.exists(local_path):
        raise HTTPException(status_code=400, detail="Локальный репозиторий не найден. Обновите список репозиториев.")
    
    try:
        # 1. Локальная синхронизация и переключение на коммит
        logger.info(f"[{action_name}] Переключение на коммит {commit_hash} в локальном репозитории {repo_name}...")
        _run_local_shell_command(f"git checkout {commit_hash}", cwd=local_path)
        
        # 2. Копирование файлов на целевой сервер
        logger.info(f"[{action_name}] Копирование файлов на {server_user}@{server_ip}:{deploy_path}...")
        rsync_command = (
            f"rsync -avz --delete --exclude='.git/' -e 'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no' "
            f"{local_path}/ {server_user}@{server_ip}:{deploy_path}/"
        )
        _run_local_shell_command(rsync_command)
        logger.info("Копирование успешно завершено.")
        
        # 3. Выполнение команды docker-compose на целевом сервере
        ssh_command = (
            f"ssh -i {ssh_key_path} -o StrictHostKeyChecking=no {server_user}@{server_ip} "
            f"'cd {deploy_path} && docker-compose -f {docker_compose_file} down --rmi all --volumes && docker-compose -f {docker_compose_file} up -d --build'"
        )
        
        logger.info(f"[{action_name}] Запуск docker-compose на {server_ip}...")
        _run_remote_shell_command(ssh_command)
        logger.info(f"[{action_name}] Docker Compose действия завершены.")

        # Обновляем коммиты в конфиге
        for r in _config.get("repositories", []):
            if r["name"] == repo_name:
                if action_name == "Откат":
                    current = r.get("current_deployed_commit")
                    previous = r.get("previous_deployed_commit")
                    r["current_deployed_commit"] = previous
                    r["previous_deployed_commit"] = current
                else: # Deploy
                    r["previous_deployed_commit"] = r.get("current_deployed_commit")
                    r["current_deployed_commit"] = commit_hash
                break
        save_config()
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"[{action_name}] Неизвестная ошибка: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка {action_name}: {e}")

# Эндпоинты API
@app.get("/repos", response_model=List[Dict])
async def get_repositories():
    """
    Возвращает список доступных репозиториев с их последними 10 коммитами.
    """
    repo_list = []
    repositories_from_config = _config.get("repositories", [])
    logger.info(f"Найдено {len(repositories_from_config)} репозиториев в конфигурации для обработки.")

    for repo_config in repositories_from_config:
        try:
            commits = get_commits_from_git_repo(repo_config["git_url"], repo_config.get("branch", "main"))
            
            repo_list.append({
                "name": repo_config["name"],
                "git_url": repo_config["git_url"],
                "branch": repo_config.get("branch", "main"),
                "server_info": repo_config["server"],
                "docker_compose_file": repo_config.get("docker_compose_file", "docker-compose.yml"),
                "commits": [commit.model_dump() for commit in commits],
                "current_deployed_commit": repo_config.get("current_deployed_commit"),
                "previous_deployed_commit": repo_config.get("previous_deployed_commit")
            })
        except HTTPException as e:
            repo_list.append({
                "name": repo_config["name"],
                "error": e.detail,
                "commits": []
            })
        except Exception as e:
             repo_list.append({
                "name": repo_config["name"],
                "error": f"Неизвестная ошибка: {str(e)}",
                "commits": []
            })

    logger.info(f"Сформирован список из {len(repo_list)} репозиториев для фронтенда.")
    return repo_list

@app.post("/deploy/{repo_name}")
async def deploy_repo(repo_name: str, request: DeployRequest):
    """
    Деплоит выбранный коммит на удаленный сервер.
    """
    logger.info(f"Получен запрос на деплой '{repo_name}' на коммит '{request.commit_hash}'.")
    repo = next((r for r in _config.get("repositories", []) if r["name"] == repo_name), None)
    if not repo:
        raise HTTPException(status_code=404, detail="Репозиторий не найден в конфигурации")

    if repo.get("current_deployed_commit") == request.commit_hash:
        raise HTTPException(status_code=400, detail="Эта версия уже развернута. Если вы хотите перезапустить, используйте кнопку 'Запустить'.")

    _perform_deploy_action(repo, request.commit_hash, "Деплой")
    return {"status": "success", "output": f"Деплой на коммит {request.commit_hash} успешно завершен."}

@app.post("/rollback/{repo_name}")
async def rollback_repo(repo_name: str):
    """
    Откатывает сервис до последней успешно запущенной версии.
    """
    logger.info(f"Получен запрос на откат для '{repo_name}'.")
    repo = next((r for r in _config.get("repositories", []) if r["name"] == repo_name), None)
    if not repo:
        raise HTTPException(status_code=404, detail="Репозиторий не найден в конфигурации")

    commit_hash_to_rollback = repo.get("previous_deployed_commit")
    if not commit_hash_to_rollback:
        raise HTTPException(status_code=400, detail="Нет предыдущей версии для отката.")

    _perform_deploy_action(repo, commit_hash_to_rollback, "Откат")
    return {"status": "success", "output": f"Откат на коммит {commit_hash_to_rollback} успешно завершен."}

@app.get("/status/{repo_name}")
async def get_repo_status(repo_name: str):
    """
    Получает отформатированный вывод `docker ps` для указанного репозитория.
    """
    logger.info(f"Получен запрос на получение статуса для '{repo_name}'.")
    repo = next((r for r in _config.get("repositories", []) if r["name"] == repo_name), None)
    if not repo:
        raise HTTPException(status_code=404, detail="Репозиторий не найден в конфигурации")

    server_ip = repo["server"]["ip"]
    server_user = repo["server"]["user"]
    ssh_key_path = repo["server"]["ssh_key"]
    deploy_path = repo["server"]["deploy_path"]
    
    ssh_command = (
        f"ssh -i {ssh_key_path} -o StrictHostKeyChecking=no {server_user}@{server_ip} "
        f"'cd {deploy_path} && docker-compose ps --format \"table {{.Image}}\t{{.Status}}\t{{.Ports}}\"'"
    )
    
    try:
        output, _ = _run_remote_shell_command(ssh_command)
        return {"status": "deployed", "output": output}
    except HTTPException as e:
        return {"status": "error", "output": e.detail}

@app.post("/run/{repo_name}")
async def run_microservice(repo_name: str):
    """
    Запускает (или перезапускает) микросервис, используя docker-compose up -d.
    """
    logger.info(f"Получен запрос на запуск '{repo_name}'.")
    repo = next((r for r in _config.get("repositories", []) if r["name"] == repo_name), None)
    if not repo:
        raise HTTPException(status_code=404, detail="Репозиторий не найден в конфигурации")

    server_ip = repo["server"]["ip"]
    server_user = repo["server"]["user"]
    ssh_key_path = repo["server"]["ssh_key"]
    deploy_path = repo["server"]["deploy_path"]
    docker_compose_file = repo.get("docker_compose_file", "docker-compose.yml")

    ssh_command = (
        f"ssh -i {ssh_key_path} -o StrictHostKeyChecking=no {server_user}@{server_ip} "
        f"'cd {deploy_path} && docker-compose -f {docker_compose_file} up -d'"
    )

    try:
        output, _ = _run_remote_shell_command(ssh_command)
        return {"status": "success", "output": f"Запуск успешно запрошен.\n{output}"}
    except HTTPException as e:
        raise e

@app.post("/stop/{repo_name}")
async def stop_microservice(repo_name: str):
    """
    Останавливает микросервис, используя docker-compose down.
    """
    logger.info(f"Получен запрос на остановку '{repo_name}'.")
    repo = next((r for r in _config.get("repositories", []) if r["name"] == repo_name), None)
    if not repo:
        raise HTTPException(status_code=404, detail="Репозиторий не найден в конфигурации")

    server_ip = repo["server"]["ip"]
    server_user = repo["server"]["user"]
    ssh_key_path = repo["server"]["ssh_key"]
    deploy_path = repo["server"]["deploy_path"]
    docker_compose_file = repo.get("docker_compose_file", "docker-compose.yml")

    ssh_command = (
        f"ssh -i {ssh_key_path} -o StrictHostKeyChecking=no {server_user}@{server_ip} "
        f"'cd {deploy_path} && docker-compose -f {docker_compose_file} down'"
    )

    try:
        output, _ = _run_remote_shell_command(ssh_command)
        return {"status": "success", "output": f"Остановка успешно запрошена.\n{output}"}
    except HTTPException as e:
        raise e

@app.post("/repos", status_code=201, response_model=Dict)
async def add_repo(repo: RepositoryConfig):
    """Добавляет новый репозиторий в конфигурацию."""
    if any(r["name"] == repo.name for r in _config.get("repositories", [])):
        raise HTTPException(status_code=409, detail="Репозиторий с таким именем уже существует.")
    
    _config["repositories"].append(repo.dict())
    save_config()
    return {"message": "Репозиторий успешно добавлен."}

@app.put("/repos/{repo_name}", response_model=Dict)
async def update_repo(repo_name: str, repo: RepositoryConfig):
    for i, r in enumerate(_config.get("repositories", [])):
        if r["name"] == repo_name:
            _config["repositories"][i] = repo.dict()
            save_config()
            return {"message": "Репозиторий успешно обновлен."}
    
    raise HTTPException(status_code=404, detail="Репозиторий не найден.")

@app.delete("/repos/{repo_name}", response_model=Dict)
async def delete_repo(repo_name: str):
    initial_count = len(_config.get("repositories", []))
    _config["repositories"] = [r for r in _config.get("repositories", []) if r["name"] != repo_name]
    
    if len(_config["repositories"]) == initial_count:
        raise HTTPException(status_code=404, detail="Репозиторий не найден.")
    
    save_config()
    # Удаляем локальный репозиторий, если он существует
    local_path = os.path.join(LOCAL_REPOS_PATH, repo_name)
    if os.path.exists(local_path):
        shutil.rmtree(local_path)
        logger.info(f"Локальный кэш репозитория {repo_name} удален.")
    
    return {"message": "Репозиторий успешно удален."}
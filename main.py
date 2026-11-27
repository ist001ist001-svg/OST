import os
import ast
import io
import re
import hmac
import json
import shutil
import secrets
import zipfile
import urllib.request
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import check_password_hash, generate_password_hash


# ==========================================
# 설정
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
PROJECTS_DIR = DATA_DIR / "projects"
DATABASE_FILE = DATA_DIR / "ist_host.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

if not app.config["SECRET_KEY"]:
    raise RuntimeError("Render 환경변수 SECRET_KEY를 설정하세요.")

ACCESS_PASSWORD = os.getenv("ACCESS_PASSWORD", "")

if len(ACCESS_PASSWORD) < 12:
    raise RuntimeError(
        "ACCESS_PASSWORD 환경변수에 12자 이상의 비밀번호를 설정하세요."
    )

ACCESS_PASSWORD_HASH = generate_password_hash(ACCESS_PASSWORD)


# ==========================================
# 데이터 저장
# ==========================================

def load_database():
    if not DATABASE_FILE.exists():
        return {"projects": [], "next_id": 1}

    try:
        with open(DATABASE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("잘못된 데이터")

        data.setdefault("projects", [])
        data.setdefault("next_id", 1)

        return data

    except Exception:
        raise RuntimeError(
            "데이터 파일을 읽을 수 없습니다. "
            "data/ist_host.json 파일을 확인하세요."
        )


def save_database(data):
    temporary = DATABASE_FILE.with_suffix(".tmp")

    with open(temporary, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=4)

    temporary.replace(DATABASE_FILE)


# ==========================================
# 로그인 및 보안
# ==========================================

def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


@app.before_request
def csrf_protection():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)

    if request.method == "POST":
        submitted = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")

        if not submitted or not hmac.compare_digest(
            submitted, expected
        ):
            abort(400, "잘못된 요청입니다. 페이지를 새로고침하세요.")


@app.context_processor
def template_values():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)

    return {"csrf_token": session["_csrf"]}


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        password = request.form.get("password", "")

        if check_password_hash(ACCESS_PASSWORD_HASH, password):
            session.clear()
            session["admin"] = True
            session["_csrf"] = secrets.token_urlsafe(32)

            flash("관리자 접속에 성공했습니다.")
            return redirect(url_for("dashboard"))

        flash("비밀번호가 올바르지 않습니다.")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@admin_required
def logout():
    session.clear()
    flash("잠금 화면으로 돌아갔습니다.")
    return redirect(url_for("login"))


# ==========================================
# 프로젝트 도구
# ==========================================

def get_project(project_id):
    data = load_database()

    for project in data["projects"]:
        if project["id"] == project_id:
            return project

    abort(404)


def project_folder(project_id):
    folder = (PROJECTS_DIR / str(project_id)).resolve()

    if PROJECTS_DIR.resolve() not in folder.parents:
        abort(400)

    folder.mkdir(parents=True, exist_ok=True)
    return folder


def safe_path(project_id, filename):
    if not filename or "\x00" in filename:
        abort(400, "파일 이름이 올바르지 않습니다.")

    root = project_folder(project_id).resolve()
    target = (root / filename).resolve()

    if target != root and root not in target.parents:
        abort(400, "허용되지 않은 파일 경로입니다.")

    return target


# ==========================================
# 홈페이지
# ==========================================

@app.route("/")
def index():
    if session.get("admin"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ==========================================
# 대시보드
# ==========================================

@app.route("/dashboard")
@admin_required
def dashboard():
    data = load_database()

    return render_template(
        "dashboard.html",
        projects=data["projects"],
        project_count=len(data["projects"])
    )


# ==========================================
# 프로젝트 생성
# 등록 개수 제한 없음
# ==========================================

@app.route("/bots/create", methods=["POST"])
@admin_required
def create_bot():
    name = request.form.get("name", "").strip()

    if not name:
        flash("봇 이름을 입력하세요.")
        return redirect(url_for("dashboard"))

    if len(name) > 100:
        flash("봇 이름은 100자 이하여야 합니다.")
        return redirect(url_for("dashboard"))

    data = load_database()

    project_id = data["next_id"]
    data["next_id"] += 1

    project = {
        "id": project_id,
        "name": name,
        "status": "중지됨"
    }

    data["projects"].append(project)
    save_database(data)

    folder = project_folder(project_id)

    main_code = '''import discord
from discord.ext import commands
import os

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    print(f"로그인 성공: {bot.user}")

# 봇 토큰은 코드에 직접 적지 말고
# 실행 환경의 환경변수로 관리하세요.

TOKEN = os.getenv("DISCORD_TOKEN")

if TOKEN:
    bot.run(TOKEN)
else:
    print("DISCORD_TOKEN 환경변수가 설정되지 않았습니다.")
'''

    (folder / "main.py").write_text(
        main_code,
        encoding="utf-8"
    )

    (folder / "requirements.txt").write_text(
        "discord.py\n",
        encoding="utf-8"
    )

    flash("새 봇 프로젝트를 만들었습니다.")
    return redirect(url_for("files", project_id=project_id))


# ==========================================
# 프로젝트 삭제
# ==========================================

@app.route("/bots/<int:project_id>/delete", methods=["POST"])
@admin_required
def delete_bot(project_id):
    data = load_database()

    project = get_project(project_id)

    data["projects"] = [
        item for item in data["projects"]
        if item["id"] != project_id
    ]

    save_database(data)

    shutil.rmtree(
        project_folder(project_id),
        ignore_errors=True
    )

    flash(f"{project['name']} 프로젝트를 삭제했습니다.")
    return redirect(url_for("dashboard"))


# ==========================================
# 파일 관리자
# ==========================================

@app.route("/bots/<int:project_id>/files")
@admin_required
def files(project_id):
    project = get_project(project_id)
    root = project_folder(project_id)

    file_list = []

    for path in root.rglob("*"):
        if path.is_file():
            file_list.append({
                "name": path.relative_to(root).as_posix(),
                "size": path.stat().st_size
            })

    file_list.sort(key=lambda item: item["name"])

    return render_template(
        "files.html",
        project=project,
        files=file_list
    )


# ==========================================
# 파일 편집
# ==========================================

@app.route(
    "/bots/<int:project_id>/edit",
    methods=["GET", "POST"]
)
@admin_required
def edit_file(project_id):
    project = get_project(project_id)

    if request.method == "POST":
        filename = request.form.get("filename", "").strip()
        content = request.form.get("content", "")

        if len(content) > 2_000_000:
            flash("파일 내용이 너무 큽니다.")
            return redirect(url_for("files", project_id=project_id))

        target = safe_path(project_id, filename)

        if target.exists() and target.is_dir():
            flash("폴더는 편집할 수 없습니다.")
            return redirect(url_for("files", project_id=project_id))

        target.parent.mkdir(parents=True, exist_ok=True)

        if target.exists():
            backup = target.with_name(target.name + ".bak")
            shutil.copy2(target, backup)

        target.write_text(content, encoding="utf-8")

        flash("파일을 저장했습니다.")
        return redirect(url_for("files", project_id=project_id))

    filename = request.args.get("file", "main.py")
    target = safe_path(project_id, filename)

    content = ""

    if target.exists() and target.is_file():
        content = target.read_text(
            encoding="utf-8",
            errors="replace"
        )

    return render_template(
        "editor.html",
        project=project,
        filename=filename,
        content=content
    )


# ==========================================
# 파일 생성
# ==========================================

@app.route(
    "/bots/<int:project_id>/new-file",
    methods=["POST"]
)
@admin_required
def new_file(project_id):
    get_project(project_id)

    filename = request.form.get("filename", "").strip()

    if not filename:
        flash("파일 이름을 입력하세요.")
        return redirect(url_for("files", project_id=project_id))

    target = safe_path(project_id, filename)

    if target.exists():
        flash("이미 존재하는 파일입니다.")
        return redirect(url_for("files", project_id=project_id))

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("", encoding="utf-8")

    flash("파일을 만들었습니다.")
    return redirect(url_for("files", project_id=project_id))


# ==========================================
# 파일 삭제
# ==========================================

@app.route(
    "/bots/<int:project_id>/delete-file",
    methods=["POST"]
)
@admin_required
def delete_file(project_id):
    get_project(project_id)

    filename = request.form.get("filename", "").strip()
    target = safe_path(project_id, filename)

    if target == project_folder(project_id).resolve():
        abort(400)

    if target.is_file():
        target.unlink()
        flash("파일을 삭제했습니다.")

    elif target.is_dir():
        shutil.rmtree(target)
        flash("폴더를 삭제했습니다.")

    else:
        flash("파일을 찾을 수 없습니다.")

    return redirect(url_for("files", project_id=project_id))


# ==========================================
# ZIP 업로드
# ==========================================

@app.route(
    "/bots/<int:project_id>/upload",
    methods=["POST"]
)
@admin_required
def upload_zip(project_id):
    get_project(project_id)

    uploaded = request.files.get("file")

    if not uploaded or not uploaded.filename.lower().endswith(".zip"):
        flash("ZIP 파일을 선택하세요.")
        return redirect(url_for("files", project_id=project_id))

    try:
        archive_data = uploaded.read(20 * 1024 * 1024 + 1)

        if len(archive_data) > 20 * 1024 * 1024:
            raise ValueError("ZIP 파일이 너무 큽니다.")

        archive = zipfile.ZipFile(io.BytesIO(archive_data))
        root = project_folder(project_id).resolve()

        entries = archive.infolist()

        if len(entries) > 500:
            raise ValueError("파일 개수가 너무 많습니다.")

        total_size = sum(item.file_size for item in entries)

        if total_size > 50 * 1024 * 1024:
            raise ValueError("압축 해제 용량이 너무 큽니다.")

        for item in entries:
            if item.is_dir():
                continue

            # 심볼릭 링크는 허용하지 않음
            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("ZIP 심볼릭 링크는 허용되지 않습니다.")

            target = (root / item.filename).resolve()

            if root not in target.parents:
                raise ValueError("잘못된 ZIP 경로입니다.")

            target.parent.mkdir(parents=True, exist_ok=True)

            with archive.open(item) as source:
                with open(target, "wb") as destination:
                    shutil.copyfileobj(source, destination)

        flash("ZIP 업로드가 완료되었습니다.")

    except Exception:
        flash("ZIP 업로드에 실패했습니다. 파일을 확인하세요.")

    return redirect(url_for("files", project_id=project_id))


# ==========================================
# GitHub 공개 저장소 가져오기
# ==========================================

@app.route(
    "/bots/<int:project_id>/github",
    methods=["POST"]
)
@admin_required
def import_github(project_id):
    get_project(project_id)

    repo_url = request.form.get("repo_url", "").strip()

    match = re.fullmatch(
        r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/?",
        repo_url
    )

    if not match:
        flash("올바른 공개 GitHub 저장소 주소를 입력하세요.")
        return redirect(url_for("files", project_id=project_id))

    owner, repo = match.groups()
    repo = repo.removesuffix(".git")

    try:
        archive_data = None

        for branch in ("main", "master"):
            url = (
                f"https://codeload.github.com/"
                f"{owner}/{repo}/zip/refs/heads/{branch}"
            )

            req = urllib.request.Request(
                url,
                headers={"User-Agent": "IST-HOST"}
            )

            try:
                with urllib.request.urlopen(req, timeout=15) as response:
                    archive_data = response.read(20 * 1024 * 1024 + 1)
                break
            except Exception:
                continue

        if not archive_data or len(archive_data) > 20 * 1024 * 1024:
            raise ValueError("저장소를 가져오지 못했습니다.")

        archive = zipfile.ZipFile(io.BytesIO(archive_data))
        root = project_folder(project_id).resolve()

        if len(archive.infolist()) > 500:
            raise ValueError("파일 개수가 너무 많습니다.")

        total_size = sum(
            item.file_size for item in archive.infolist()
        )

        if total_size > 50 * 1024 * 1024:
            raise ValueError("압축 해제 용량이 너무 큽니다.")

        for item in archive.infolist():
            if item.is_dir():
                continue

            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("심볼릭 링크는 허용되지 않습니다.")

            parts = Path(item.filename).parts

            if len(parts) < 2:
                continue

            relative = Path(*parts[1:])
            target = (root / relative).resolve()

            if root not in target.parents:
                raise ValueError("잘못된 파일 경로입니다.")

            target.parent.mkdir(parents=True, exist_ok=True)

            with archive.open(item) as source:
                with open(target, "wb") as destination:
                    shutil.copyfileobj(source, destination)

        flash("GitHub 저장소를 가져왔습니다.")

    except Exception:
        flash("GitHub 가져오기에 실패했습니다.")

    return redirect(url_for("files", project_id=project_id))


# ==========================================
# Python 문법 검사
# ==========================================

@app.route(
    "/bots/<int:project_id>/check"
)
@admin_required
def check_code(project_id):
    project = get_project(project_id)
    root = project_folder(project_id)

    results = []

    for path in root.rglob("*.py"):
        try:
            source = path.read_text(
                encoding="utf-8",
                errors="replace"
            )

            ast.parse(source)

            results.append({
                "file": path.relative_to(root).as_posix(),
                "status": "success",
                "message": "문법 오류가 없습니다."
            })

        except SyntaxError as error:
            results.append({
                "file": path.relative_to(root).as_posix(),
                "status": "error",
                "message": f"{error.lineno}번째 줄: {error.msg}"
            })

        except Exception as error:
            results.append({
                "file": path.relative_to(root).as_posix(),
                "status": "error",
                "message": str(error)
            })

    requirements = root / "requirements.txt"
    main_file = root / "main.py"

    if not main_file.exists():
        results.append({
            "file": "main.py",
            "status": "error",
            "message": "main.py 파일이 없습니다."
        })

    if not requirements.exists():
        results.append({
            "file": "requirements.txt",
            "status": "error",
            "message": "requirements.txt 파일이 없습니다."
        })

    return render_template(
        "check.html",
        project=project,
        results=results
    )


# ==========================================
# 봇 실행 버튼
# 실제 실행 엔진은 아직 연결되지 않음
# ==========================================

@app.route(
    "/bots/<int:project_id>/action/<action>",
    methods=["POST"]
)
@admin_required
def bot_action(project_id, action):
    get_project(project_id)

    if action not in ("start", "stop", "restart"):
        abort(400)

    flash(
        "봇 실행 엔진이 아직 연결되지 않았습니다. "
        "프로젝트 파일 관리와 코드 검사는 사용할 수 있습니다."
    )

    return redirect(url_for("dashboard"))


# ==========================================
# 오류 페이지
# ==========================================

@app.errorhandler(400)
def bad_request(error):
    return str(error.description), 400


@app.errorhandler(403)
def forbidden(error):
    return "접근 권한이 없습니다.", 403


@app.errorhandler(404)
def not_found(error):
    return "페이지를 찾을 수 없습니다.", 404


@app.errorhandler(413)
def too_large(error):
    return "업로드 파일이 너무 큽니다.", 413


# ==========================================
# 실행
# ==========================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 10000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
)

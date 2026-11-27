import os
import re
import ast
import io
import json
import uuid
import shutil
import zipfile
import secrets
import urllib.request
from pathlib import Path
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.utils import secure_filename


# =========================================
# 기본 설정
# =========================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
PROJECT_DIR = DATA_DIR / "projects"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PROJECT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY", secrets.token_hex(32)
)

database_url = os.getenv("DATABASE_URL", "sqlite:///ist_host.db")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

db = SQLAlchemy(app)


# =========================================
# 데이터베이스
# =========================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    avatar = db.Column(db.String(300))


class BotProject(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    status = db.Column(db.String(30), default="stopped")
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )


with app.app_context():
    db.create_all()


# =========================================
# 디스코드 OAuth2
# =========================================

oauth = OAuth(app)

oauth.register(
    name="discord",
    client_id=os.getenv("DISCORD_CLIENT_ID"),
    client_secret=os.getenv("DISCORD_CLIENT_SECRET"),
    access_token_url="https://discord.com/api/oauth2/token",
    authorize_url="https://discord.com/api/oauth2/authorize",
    api_base_url="https://discord.com/api/",
    client_kwargs={
        "scope": "identify"
    }
)


# =========================================
# CSRF 보호
# =========================================

@app.before_request
def csrf_check():
    if request.method == "POST":
        token = session.get("_csrf_token")
        submitted = request.form.get("_csrf_token")

        if not token or not submitted or not secrets.compare_digest(
            token, submitted
        ):
            abort(400, "잘못된 요청입니다. 페이지를 새로고침하세요.")


@app.context_processor
def inject_csrf():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)

    return {
        "csrf_token": session["_csrf_token"]
    }


# =========================================
# 로그인 확인
# =========================================

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    return db.session.get(User, user_id)


def get_project(project_id):
    project = db.session.get(BotProject, project_id)

    if not project:
        abort(404)

    if project.owner_id != session.get("user_id"):
        abort(403)

    return project


def project_path(project):
    path = PROJECT_DIR / str(project.owner_id) / str(project.id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_file_path(project, filename):
    root = project_path(project).resolve()
    target = (root / filename).resolve()

    if target != root and root not in target.parents:
        abort(400, "잘못된 파일 경로입니다.")

    return target


# =========================================
# 홈페이지
# =========================================

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# =========================================
# 디스코드 로그인
# =========================================

@app.route("/login")
def login():
    if not os.getenv("DISCORD_CLIENT_ID") or not os.getenv(
        "DISCORD_CLIENT_SECRET"
    ):
        flash("Discord OAuth 환경변수를 설정해야 합니다.")
        return redirect(url_for("index"))

    redirect_uri = url_for(
        "discord_callback",
        _external=True
    )

    return oauth.discord.authorize_redirect(redirect_uri)


@app.route("/callback")
def discord_callback():
    try:
        token = oauth.discord.authorize_access_token()
        response = oauth.discord.get("users/@me")
        discord_user = response.json()

        discord_id = str(discord_user["id"])

        user = User.query.filter_by(
            discord_id=discord_id
        ).first()

        avatar_hash = discord_user.get("avatar")

        avatar_url = None

        if avatar_hash:
            avatar_url = (
                f"https://cdn.discordapp.com/avatars/"
                f"{discord_id}/{avatar_hash}.png"
            )

        if not user:
            user = User(
                discord_id=discord_id,
                username=discord_user["username"],
                avatar=avatar_url
            )
            db.session.add(user)
        else:
            user.username = discord_user["username"]
            user.avatar = avatar_url

        db.session.commit()

        session.clear()
        session["user_id"] = user.id

        flash("로그인 성공!")
        return redirect(url_for("dashboard"))

    except Exception as error:
        app.logger.exception("Discord OAuth failed")
        flash("디스코드 로그인에 실패했습니다.")
        return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃했습니다.")
    return redirect(url_for("index"))


# =========================================
# 대시보드
# =========================================

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()

    projects = BotProject.query.filter_by(
        owner_id=user.id
    ).order_by(
        BotProject.created_at.desc()
    ).all()

    return render_template(
        "dashboard.html",
        user=user,
        projects=projects,
        project_count=len(projects)
    )


# =========================================
# 봇 프로젝트 생성
# 봇 등록 개수 제한 없음
# =========================================

@app.route("/bots/create", methods=["POST"])
@login_required
def create_bot():
    name = request.form.get("name", "").strip()

    if not name:
        flash("봇 이름을 입력하세요.")
        return redirect(url_for("dashboard"))

    if len(name) > 100:
        flash("봇 이름은 100자 이하여야 합니다.")
        return redirect(url_for("dashboard"))

    project = BotProject(
        name=name,
        owner_id=session["user_id"]
    )

    db.session.add(project)
    db.session.commit()

    folder = project_path(project)

    (folder / "main.py").write_text(
        "# IST HOST Discord Bot\n"
        "import discord\n"
        "from discord.ext import commands\n\n"
        "bot = commands.Bot(command_prefix='!', intents=discord.Intents.default())\n\n"
        "@bot.event\n"
        "async def on_ready():\n"
        "    print(f'로그인 성공: {bot.user}')\n\n"
        "# 실제 실행을 위해서는 별도의 안전한 실행 엔진이 필요합니다.\n",
        encoding="utf-8"
    )

    (folder / "requirements.txt").write_text(
        "discord.py\n",
        encoding="utf-8"
    )

    flash("봇 프로젝트를 만들었습니다.")
    return redirect(url_for("files", project_id=project.id))


# =========================================
# 봇 삭제
# =========================================

@app.route("/bots/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_bot(project_id):
    project = get_project(project_id)

    folder = project_path(project)

    shutil.rmtree(folder, ignore_errors=True)

    db.session.delete(project)
    db.session.commit()

    flash("프로젝트를 삭제했습니다.")
    return redirect(url_for("dashboard"))


# =========================================
# 파일 관리자
# =========================================

@app.route("/bots/<int:project_id>/files")
@login_required
def files(project_id):
    project = get_project(project_id)
    root = project_path(project)

    file_list = []

    for path in root.rglob("*"):
        if path.is_file():
            relative = path.relative_to(root).as_posix()

            file_list.append({
                "name": relative,
                "size": path.stat().st_size
            })

    file_list.sort(key=lambda item: item["name"])

    return render_template(
        "files.html",
        project=project,
        files=file_list
    )


# =========================================
# 파일 편집
# =========================================

@app.route(
    "/bots/<int:project_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_file(project_id):
    project = get_project(project_id)

    filename = request.args.get("file", "main.py")
    target = safe_file_path(project, filename)

    if request.method == "POST":
        filename = request.form.get("filename", "").strip()
        content = request.form.get("content", "")

        if not filename or len(content) > 2_000_000:
            flash("파일 이름 또는 내용이 올바르지 않습니다.")
            return redirect(url_for(
                "files", project_id=project.id
            ))

        target = safe_file_path(project, filename)
        target.parent.mkdir(parents=True, exist_ok=True)

        if target.exists():
            backup = target.with_name(target.name + ".bak")
            shutil.copy2(target, backup)

        target.write_text(content, encoding="utf-8")

        flash("파일을 저장했습니다.")
        return redirect(url_for(
            "files", project_id=project.id
        ))

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


# =========================================
# 새 파일 생성
# =========================================

@app.route(
    "/bots/<int:project_id>/new-file",
    methods=["POST"]
)
@login_required
def new_file(project_id):
    project = get_project(project_id)

    filename = request.form.get("filename", "").strip()

    if not filename:
        flash("파일 이름을 입력하세요.")
        return redirect(url_for("files", project_id=project.id))

    target = safe_file_path(project, filename)

    if target.exists():
        flash("이미 존재하는 파일입니다.")
        return redirect(url_for("files", project_id=project.id))

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("", encoding="utf-8")

    flash("파일을 생성했습니다.")
    return redirect(url_for("files", project_id=project.id))


# =========================================
# 파일 삭제
# =========================================

@app.route(
    "/bots/<int:project_id>/delete-file",
    methods=["POST"]
)
@login_required
def delete_file(project_id):
    project = get_project(project_id)

    filename = request.form.get("filename", "")
    target = safe_file_path(project, filename)

    if target.is_file():
        target.unlink()
        flash("파일을 삭제했습니다.")

    elif target.is_dir():
        shutil.rmtree(target)
        flash("폴더를 삭제했습니다.")

    return redirect(url_for("files", project_id=project.id))


# =========================================
# ZIP 업로드
# =========================================

@app.route(
    "/bots/<int:project_id>/upload",
    methods=["POST"]
)
@login_required
def upload_zip(project_id):
    project = get_project(project_id)

    uploaded = request.files.get("file")

    if not uploaded or not uploaded.filename.endswith(".zip"):
        flash("ZIP 파일을 선택하세요.")
        return redirect(url_for("files", project_id=project.id))

    try:
        archive = zipfile.ZipFile(io.BytesIO(uploaded.read()))
        root = project_path(project).resolve()

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

            target = (root / item.filename).resolve()

            if root not in target.parents:
                raise ValueError("잘못된 ZIP 경로입니다.")

            target.parent.mkdir(parents=True, exist_ok=True)

            with archive.open(item) as source:
                with open(target, "wb") as destination:
                    shutil.copyfileobj(source, destination)

        flash("ZIP 프로젝트를 업로드했습니다.")

    except Exception:
        flash("ZIP 업로드에 실패했습니다.")

    return redirect(url_for("files", project_id=project.id))


# =========================================
# GitHub 공개 저장소 가져오기
# =========================================

@app.route(
    "/bots/<int:project_id>/github",
    methods=["POST"]
)
@login_required
def import_github(project_id):
    project = get_project(project_id)

    repo_url = request.form.get("repo_url", "").strip()

    match = re.fullmatch(
        r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/?",
        repo_url
    )

    if not match:
        flash("올바른 공개 GitHub 저장소 주소를 입력하세요.")
        return redirect(url_for("files", project_id=project.id))

    owner, repo = match.groups()
    repo = repo.removesuffix(".git")

    try:
        headers = {"User-Agent": "IST-HOST"}

        branches = ["main", "master"]
        archive_data = None

        for branch in branches:
            url = (
                f"https://codeload.github.com/"
                f"{owner}/{repo}/zip/refs/heads/{branch}"
            )

            req = urllib.request.Request(url, headers=headers)

            try:
                with urllib.request.urlopen(req, timeout=15) as response:
                    archive_data = response.read(20 * 1024 * 1024 + 1)
                break
            except Exception:
                continue

        if not archive_data or len(archive_data) > 20 * 1024 * 1024:
            raise ValueError("저장소를 가져오지 못했습니다.")

        archive = zipfile.ZipFile(io.BytesIO(archive_data))
        root = project_path(project).resolve()

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

            parts = Path(item.filename).parts

            # GitHub ZIP의 최상위 폴더 이름 제거
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

        flash("GitHub 프로젝트를 가져왔습니다.")

    except Exception:
        flash("GitHub 가져오기에 실패했습니다.")

    return redirect(url_for("files", project_id=project.id))


# =========================================
# Python 문법 검사
# =========================================

@app.route(
    "/bots/<int:project_id>/check",
    methods=["GET", "POST"]
)
@login_required
def check_code(project_id):
    project = get_project(project_id)
    root = project_path(project)

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
                "message": (
                    f"{error.lineno}번째 줄: {error.msg}"
                )
            })

        except Exception as error:
            results.append({
                "file": path.relative_to(root).as_posix(),
                "status": "error",
                "message": str(error)
            })

    return render_template(
        "check.html",
        project=project,
        results=results
    )


# =========================================
# 봇 실행 버튼
# 현재는 실행 엔진 연결 전 단계
# =========================================

@app.route(
    "/bots/<int:project_id>/action/<action>",
    methods=["POST"]
)
@login_required
def bot_action(project_id, action):
    project = get_project(project_id)

    if action not in ("start", "stop", "restart"):
        abort(400)

    flash(
        "아직 봇 실행 엔진이 연결되지 않았습니다. "
        "현재 웹사이트는 프로젝트 관리 기능을 제공합니다."
    )

    return redirect(url_for("dashboard"))


# =========================================
# 오류 처리
# =========================================

@app.errorhandler(403)
def forbidden(error):
    return "접근 권한이 없습니다.", 403


@app.errorhandler(404)
def not_found(error):
    return "페이지를 찾을 수 없습니다.", 404


@app.errorhandler(413)
def too_large(error):
    return "업로드 파일이 너무 큽니다.", 413


# =========================================
# 서버 실행
# =========================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 10000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
  )

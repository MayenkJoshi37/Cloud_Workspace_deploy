# app.py  (REVISED for Render deployment - docker operations replaced with UI-only flows)
from flask import Flask, render_template, request, redirect, url_for, flash, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os, uuid, yaml, logging

# Optional: keep subprocess if you ever run docker locally; not used on Render.
import subprocess

# ---------- Config ----------
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret")
    # Accept DATABASE_URL from env (Render will provide). Convert postgres:// -> postgresql:// for SQLAlchemy.
    db_url = os.environ.get("DATABASE_URL", None)
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = db_url or os.environ.get("DATABASE_URL", "sqlite:///cloud_workspaces.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Uploads: Render filesystem is ephemeral; consider S3 for persistence.
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join("/tmp", "uploads"))
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 5 * 1024 * 1024))  # bytes

    ALLOWED_EXTENSIONS = {"yml", "yaml", "env", "txt"}  # allow these for uploads

# ---------- App & DB ----------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---------- Models ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    workspaces = db.relationship("Workspace", backref="owner", lazy=True)

class Workspace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    yaml_filename = db.Column(db.String(256), nullable=False)
    env_filename = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(32), default="stopped")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# Create DB tables (safe for dev). On production use migrations (Flask-Migrate).
with app.app_context():
    db.create_all()

# ---------- Helpers ----------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

def save_uploaded_file(file_storage):
    """Save securely to UPLOAD_FOLDER and return saved filename."""
    if not file_storage or file_storage.filename == "":
        return None
    filename = secure_filename(file_storage.filename)
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    if ext and ext not in app.config["ALLOWED_EXTENSIONS"]:
        return None
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    saved_name = f"{uuid.uuid4().hex}_{filename}"
    path = os.path.join(app.config["UPLOAD_FOLDER"], saved_name)
    file_storage.save(path)
    return saved_name

def read_compose_services(yaml_path):
    """Return services dict from compose file so UI can display services and resources."""
    try:
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f) or {}
        services = []
        for name, cfg in data.get("services", {}).items():
            services.append({"name": name, "image": cfg.get("image"), "build": cfg.get("build")})
        return services
    except Exception as e:
        current_app.logger.error(f"read_compose_services error: {e}")
        return []

# ---------- Routes ----------
@app.route("/auth/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if not u or not p:
            flash("Username and password required", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(username=u).first():
            flash("Username exists", "danger")
            return redirect(url_for("register"))
        user = User(username=u, password_hash=generate_password_hash(p))
        db.session.add(user)
        db.session.commit()
        flash("Registered!", "success")
        return redirect(url_for("login"))
    return render_template("login.html", register=True)

@app.route("/auth/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        user = User.query.filter_by(username=u).first()
        if user and check_password_hash(user.password_hash, p):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html", register=False)

@app.route("/auth/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user_workspaces = Workspace.query.filter_by(user_id=current_user.id).all()
    # Rather than running docker-compose, we inspect the compose YAML on disk (if present)
    for ws in user_workspaces:
        if not getattr(ws, "yaml_filename", None):
            ws.status = ws.status or "stopped"
            continue
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
        if not os.path.exists(path):
            if ws.status != "stopped":
                ws.status = "stopped"
                db.session.commit()
            continue
        # If a compose file exists, mark as 'available' (or keep existing running/stopped state).
        if ws.status not in ("running", "stopped", "deployed"):
            ws.status = "available"
            db.session.commit()

    workspaces = Workspace.query.filter_by(user_id=current_user.id).all()
    # For each workspace include basic service list
    for ws in workspaces:
        compose_path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
        ws._services = read_compose_services(compose_path) if os.path.exists(compose_path) else []
    return render_template("dashboard.html", workspaces=workspaces)

@app.route("/workspace/create", methods=["GET", "POST"])
@login_required
def create_workspace():
    if request.method == "POST":
        name = request.form.get("name", "Unnamed workspace").strip()
        compose_file = request.files.get("yaml_file")
        env_file = request.files.get("env_file")

        if not compose_file or compose_file.filename == "":
            flash("YAML file required", "danger")
            return redirect(url_for("create_workspace"))

        compose_saved = save_uploaded_file(compose_file)
        if not compose_saved:
            flash("Compose file type not allowed", "danger")
            return redirect(url_for("create_workspace"))

        ws = Workspace(name=name, yaml_filename=compose_saved, user_id=current_user.id)
        db.session.add(ws)
        db.session.commit()  # to get ws.id

        # If env uploaded - save it and create a build dir with Dockerfile (but DO NOT run Docker on Render)
        if env_file and env_file.filename != "":
            env_saved = save_uploaded_file(env_file)
            if env_saved:
                ws.env_filename = env_saved
                db.session.commit()

                build_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], f"build_{ws.id}")
                os.makedirs(build_dir, exist_ok=True)
                # create a Dockerfile for local use (optional)
                dockerfile_path = os.path.join(build_dir, "Dockerfile")
                with open(dockerfile_path, "w") as df:
                    df.write("""FROM python:3.11-slim
# This Dockerfile is informational: Render web service won't build/run it.
RUN apt-get update && apt-get install -y build-essential
WORKDIR /workspace
COPY environment.yml /tmp/environment.yml
# Add your build steps here if you want to build locally.
""")
                # copy env file as environment.yml for local build
                try:
                    import shutil
                    shutil.copy(os.path.join(current_app.config["UPLOAD_FOLDER"], env_saved),
                                os.path.join(build_dir, "environment.yml"))
                except Exception as e:
                    current_app.logger.error(f"copy env to build_dir failed: {e}")

        flash("Workspace created successfully", "success")
        return redirect(url_for("dashboard"))
    return render_template("workspace.html")

# NOTE: on Render we DO NOT run docker-compose. The run/stop endpoints update status only.
@app.route("/workspace/run/<int:id>")
@login_required
def run_workspace(id):
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)
    if ws.user_id != current_user.id:
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    # If compose exists, simulate a "deployed" state and show service info.
    compose_path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
    if not os.path.exists(compose_path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))

    # Replace actual Docker operations with a simulated deployment state
    ws.status = "deployed"
    db.session.commit()
    flash("Workspace marked as deployed (note: Docker cannot run on Render web instance).", "success")
    return redirect(url_for("dashboard"))

@app.route("/workspace/stop/<int:id>")
@login_required
def stop_workspace(id):
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)
    if ws.user_id != current_user.id:
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    ws.status = "stopped"
    db.session.commit()
    flash("Workspace stopped (UI-only)", "info")
    return redirect(url_for("dashboard"))

@app.route("/workspace/delete/<int:id>")
@login_required
def delete_workspace(id):
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)

    # remove files (best-effort)
    try:
        if ws.yaml_filename:
            os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename))
        if ws.env_filename:
            os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], ws.env_filename))
        build_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], f"build_{ws.id}")
        if os.path.exists(build_dir):
            import shutil
            shutil.rmtree(build_dir)
    except Exception as e:
        current_app.logger.warning(f"delete workspace files issue: {e}")

    db.session.delete(ws)
    db.session.commit()
    flash("Workspace deleted", "warning")
    return redirect(url_for("dashboard"))

@app.route("/workspace/refresh-status/<int:id>")
@login_required
def refresh_workspace_status(id):
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)
    if ws.user_id != current_user.id:
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    # On Render we cannot query docker; simply reflect file presence or current status.
    compose_path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
    if not os.path.exists(compose_path):
        ws.status = "stopped"
    else:
        # keep existing status or set available
        if ws.status not in ("deployed", "running"):
            ws.status = "available"
    db.session.commit()
    flash(f"Workspace is {ws.status}", "info")
    return redirect(url_for("dashboard"))

@app.route("/workspace/cost-comparison/<int:id>")
@login_required
def cost_comparison(id):
    # re-use your analyzer functions - they don't require docker running
    ws = db.session.get(Workspace, id)
    if ws is None:
        abort(404)
    if ws.user_id != current_user.id:
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], ws.yaml_filename)
    if not os.path.exists(path):
        flash("Workspace file not found", "danger")
        return redirect(url_for("dashboard"))
    resources = analyze_docker_compose_resources(path)
    cost_data = calculate_cloud_costs(resources)
    return render_template("cost_comparison.html", workspace=ws, resources=resources, cost_data=cost_data)

# ---------- Existing helper functions reused (unchanged) ----------
def analyze_docker_compose_resources(yaml_path):
    try:
        with open(yaml_path, "r") as file:
            compose_data = yaml.safe_load(file) or {}
        total_cpu = total_memory = 0
        services = []
        if "services" in compose_data:
            for name, cfg in compose_data["services"].items():
                cpu = mem = 0
                if "deploy" in cfg and "resources" in cfg["deploy"]:
                    limits = cfg["deploy"]["resources"].get("limits", {})
                    if "cpus" in limits:
                        try:
                            cpu = float(limits["cpus"])
                        except Exception:
                            cpu = 0
                    if "memory" in limits:
                        m = str(limits["memory"])
                        try:
                            if m.lower().endswith("g"):
                                mem = float(m[:-1])
                            elif m.lower().endswith("m"):
                                mem = float(m[:-1]) / 1024
                            elif m.lower().endswith("k"):
                                mem = float(m[:-1]) / (1024*1024)
                        except Exception:
                            mem = 0
                cpu = cpu or 1.0
                mem = mem or 1.0
                total_cpu += cpu; total_memory += mem
                services.append({"name": name, "cpu": cpu, "memory": mem})
        return {"total_cpu": total_cpu, "total_memory": total_memory, "total_storage": len(services) * 10, "services": services}
    except Exception as e:
        current_app.logger.error(f"Error analyzing compose file: {str(e)}")
        return {"total_cpu": 2, "total_memory": 4, "total_storage": 20, "services": []}

def calculate_cloud_costs(resources):
    cpu, memory, storage = (resources["total_cpu"], resources["total_memory"], resources["total_storage"])
    pricing = {
        "aws": {"ec2_t3_medium": {"cpu": 2, "memory": 4, "price": 0.0416}, "storage": 0.10, "name": "AWS"},
        "azure": {"b2s": {"cpu": 2, "memory": 4, "price": 0.0408}, "storage": 0.12, "name": "Azure"},
        "gcp": {"e2_medium": {"cpu": 2, "memory": 4, "price": 0.0335}, "storage": 0.08, "name": "GCP"},
        "digitalocean": {"s_2vcpu_4gb": {"cpu": 2, "memory": 4, "price": 0.024}, "storage": 0.10, "name": "DigitalOcean"},
    }
    results = {}
    for provider, data in pricing.items():
        # Find cheapest matching instance (very simple)
        best = None
        for k, inst in data.items():
            if isinstance(inst, dict) and "cpu" in inst:
                if inst["cpu"] >= cpu and inst["memory"] >= memory:
                    if not best or inst["price"] < best["price"]:
                        best = inst
        if best:
            hourly = best["price"]
            monthly = hourly * 24 * 30
            total = monthly + data["storage"] * storage
            results[provider] = {"name": data["name"], "instance_type": best, "hourly_cost": hourly, "monthly_cost": monthly, "storage_cost": data["storage"] * storage, "total_monthly": total}
    return results

# Keep function to patch compose with build (useful if you build locally)
def patch_compose_with_build(compose_path, build_dir):
    with open(compose_path) as f:
        data = yaml.safe_load(f) or {}
    for svc, cfg in data.get("services", {}).items():
        if "code" in svc or "code-server" in str(cfg.get("image", "")):
            cfg.pop("image", None)
            cfg["build"] = build_dir
    with open(compose_path, "w") as f:
        yaml.safe_dump(data, f)

# ---------- Run ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # debug=True only for local dev. In Render production, gunicorn will be used.
    app.run(debug=True, host="0.0.0.0", port=port)

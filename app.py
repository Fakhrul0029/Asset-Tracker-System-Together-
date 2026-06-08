from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import logging

app = Flask(__name__)
app.secret_key = "change_this_secret_key"

# -----------------------------
# LOGGING
# -----------------------------
logging.basicConfig(level=logging.INFO)

# -----------------------------
# FAKE IN-MEMORY DATABASE (safe fallback)
# Replace with PostgreSQL later if needed
# -----------------------------
users = {
    "admin@jtdi.gov.my": {
        "password": "admin123",
        "role": "admin"
    }
}

assets = [
    {"id": 1, "name": "Laptop", "status": "Active"},
    {"id": 2, "name": "Printer", "status": "Maintenance"}
]

# -----------------------------
# LOGIN REQUIRED DECORATOR (FIXED - NO RECURSION)
# -----------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# -----------------------------
# HOME ROUTE (NO LOOP)
# -----------------------------
@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# -----------------------------
# LOGIN
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = users.get(email)

        if user and user["password"] == password:
            session["user"] = email
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid credentials", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


# -----------------------------
# LOGOUT
# -----------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------
# DASHBOARD
# -----------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    try:
        return render_template(
            "dashboard.html",
            user=session.get("user"),
            assets=assets
        )
    except Exception as e:
        logging.error(f"Dashboard error: {e}")
        return redirect(url_for("login"))


# -----------------------------
# ASSETS LIST
# -----------------------------
@app.route("/assets")
@login_required
def asset_list():
    return render_template("assets.html", assets=assets)


# -----------------------------
# ADD ASSET
# -----------------------------
@app.route("/assets/add", methods=["GET", "POST"])
@login_required
def add_asset():
    if request.method == "POST":
        name = request.form.get("name")

        new_id = max([a["id"] for a in assets]) + 1 if assets else 1

        assets.append({
            "id": new_id,
            "name": name,
            "status": "Active"
        })

        return redirect(url_for("asset_list"))

    return render_template("add.html")


# -----------------------------
# EDIT ASSET
# -----------------------------
@app.route("/assets/edit/<int:asset_id>", methods=["GET", "POST"])
@login_required
def edit_asset(asset_id):
    asset = next((a for a in assets if a["id"] == asset_id), None)

    if not asset:
        return redirect(url_for("asset_list"))

    if request.method == "POST":
        asset["name"] = request.form.get("name")
        asset["status"] = request.form.get("status")
        return redirect(url_for("asset_list"))

    return render_template("edit.html", asset=asset)


# -----------------------------
# VIEW ASSET
# -----------------------------
@app.route("/assets/view/<int:asset_id>")
@login_required
def view_asset(asset_id):
    asset = next((a for a in assets if a["id"] == asset_id), None)

    if not asset:
        return redirect(url_for("asset_list"))

    return render_template("view.html", asset=asset)


# -----------------------------
# ADMIN PAGE (SAFE PLACEHOLDER)
# -----------------------------
@app.route("/admin")
@login_required
def admin():
    if session.get("role") != "admin":
        return redirect(url_for("dashboard"))

    return render_template("admin.html", users=users)


# -----------------------------
# ERROR HANDLERS (PREVENT CRASH LOOPS)
# -----------------------------
@app.errorhandler(500)
def server_error(e):
    logging.error(f"Server error: {e}")
    return redirect(url_for("login"))


# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)

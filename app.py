from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf import CSRFProtect
import os

app = Flask(__name__)

# Required for sessions + CSRF
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

# Enable CSRF protection globally
csrf = CSRFProtect(app)


@app.route("/")
def home():
    # change this if your app has a dashboard
    if "user" in session:
        return "Logged in"
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # TODO: replace with your real auth logic
        if username == "admin" and password == "admin":
            session["user"] = username
            return redirect(url_for("home"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)

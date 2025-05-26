from cs50 import SQL
from flask import Flask, flash, render_template, request, redirect, session
from flask_session import Session
from helpers import login_required, logged_out_only
from encryption import encrypt, decrypt
import re
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True)
    app.run(use_reloader=True)

app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///data.db")


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    return render_template("index.html", s=session["s"])


@app.route("/login", methods=["GET", "POST"])
@logged_out_only
def login():
    if request.method == "POST":
        session.clear()
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Please provide a username and password", "error")
            return render_template("login.html"), 403

        rows = db.execute(
            "SELECT * FROM users WHERE username = :username;",
            username=username,
        )

        if len(rows) != 1:
            flash("Invalid username or user does not exist", "error")
            return render_template("login.html"), 403

        # Decrypt secrets, if the the first return is True, then redirect to the Home page and forward decrypted secrets to the Home page, otherwise, redirect to the login page with error message

        user_matched, secrets = decrypt(username, password, rows[0]["s"])
        if not user_matched:
            flash("Invalid username or password", "error")
            return render_template("login.html"), 403

        session["user_id"] = rows[0]["id"]
        session["s"] = secrets

        return redirect("/")
    elif request.method == "GET":
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
@logged_out_only
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            flash("Please provide a username and password", "error")
            return render_template("register.html"), 403

        if password != confirmation:
            flash("Passwords do not match", "error")
            return render_template("register.html"), 403

        if not re.compile("^[A-Za-z][A-Za-z0-9_]{4,}$").match(username):
            flash(
                "Username should be: 5+ characters, and contains only characters and digits and underscores",
                "error",
            )
            return render_template("register.html"), 403

        s = encrypt(username, password)

        try:
            new_user_id = db.execute(
                "INSERT INTO users (username, s) VALUES (:username, :s);",
                username=username,
                s=s,
            )
        except ValueError:
            flash(f"Username {username} already exists", "error")
            return render_template("register.html"), 403

        flash(f"User {username} Registered successfully", "success")
        if request.args.get("redirect_to"):
            return redirect(request.args.get("redirect_to"))
        else:
            return redirect("/")
    elif request.method == "GET":
        return render_template("register.html")

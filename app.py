import uuid
from cs50 import SQL
from flask import Flask, flash, render_template, request, redirect, session
from flask_session import Session
from helpers import login_required, logged_out_only, print_c
from encryption import encrypt_secrets, decrypt_secrets, encrypt, decrypt
import re
from pyotp import TOTP, HOTP
from time import time
from datetime import datetime, timedelta
import ast

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


def digest_secrets(secret: dict):
    otp = (
        TOTP(
            secret["secret_key"],
            digits=int(secret["digits"]),
            interval=int(secret["period"]),
            issuer=secret["issuer"],
            name=secret["account"],
            digest=secret["algorithm"],
        ).now()
        if secret["otp_type"] == "totp"
        else HOTP(
            secret["secret_key"],
            digits=int(secret["digits"]),
            issuer=secret["issuer"],
            name=secret["account"],
            digest=secret["algorithm"],
            initial_count=int(secret["counter"]),
        ).at(int(secret["counter"]))
    )

    interval = int(secret["period"]) if secret["otp_type"] == "totp" else None
    remaining_seconds = interval - (time() % interval) if interval else 100

    ends_at = (
        (datetime.now() + timedelta(seconds=remaining_seconds)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        if secret["otp_type"] == "totp"
        else None
    )

    counter = int(secret["counter"]) if secret["otp_type"] == "hotp" else None

    return {
        "id": secret["id"],
        "issuer": secret["issuer"],
        "account": secret["account"],
        "otp_type": secret["otp_type"],
        "otp": otp,
        "ends_at": ends_at,
        "interval": interval,
        "remaining_seconds": remaining_seconds,
        "counter": counter,
    }


@app.route("/")
@login_required
def index():
    OTPs = list(
        map(
            digest_secrets,
            session["s"],
        )
    )

    refresh_after = (
        sorted(
            OTPs,
            key=lambda x: x["remaining_seconds"] or 100,
        )[
            0
        ]["remaining_seconds"]
        if len(OTPs) > 0
        else None
    )
    return render_template("index.html", s=OTPs, refresh_after=refresh_after)


@app.route("/login", methods=["GET", "POST"])
@logged_out_only
def login():
    if request.method == "POST":
        session.clear()
        username = request.form.get("username").strip()
        password = request.form.get("password")
        if not username or not password:
            flash("Please provide a username and password", "error")
            return render_template("login.html"), 403

        rows = db.execute(
            "SELECT * FROM users WHERE username = :username COLLATE NOCASE;",
            username=username,
        )

        if len(rows) != 1:
            flash("Invalid username or user does not exist", "error")
            return render_template("login.html"), 403

        # Decrypt secrets, if the the first return is True, then redirect to the Home page and forward decrypted secrets to the Home page, otherwise, redirect to the login page with error message

        user_matched, secrets = decrypt_secrets(
            str(rows[0]["username"]), password, str(rows[0]["s"])
        )
        if not user_matched:
            flash("Invalid username or password", "error")
            return render_template("login.html"), 403
        session["user_id"] = rows[0]["id"]
        session["s"] = ast.literal_eval(secrets)
        session["p"] = encrypt(password, str(rows[0]["s"]))

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
        if not re.compile("^.{8,}$").match(password):
            flash(
                "Password should be 6+ characters",
                "error",
            )
            return render_template("register.html"), 403

        s = encrypt_secrets(username, password)

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


@app.route("/add_secret", methods=["GET", "POST"])
@login_required
def add_secret():
    if request.method == "POST":
        issuer = request.form.get("issuer")
        account = request.form.get("account")
        secret = request.form.get("secret")
        otp_type = request.form.get("otp_type", "totp")  # optional
        algorithm = request.form.get("algorithm", "SHA1")  # optional
        digits = request.form.get("digits", "6")  # optional
        period = request.form.get("period", "30")  # optional
        counter = request.form.get("counter", "0")  # optional

        if not issuer:
            flash(
                "Please provide a name to label your code with (service/website/application name at least)",
                "error",
            )
            return render_template("add_secret.html"), 403

        if not secret:
            flash(
                "Please, provide a secret and the OTP type",
                "error",
            )
            return render_template("add_secret.html"), 403

        if otp_type not in ["totp", "hotp"]:
            flash("Invalid OTP type", "error")
            return render_template("add_secret.html"), 403

        if algorithm not in ["sha1", "sha256", "sha512"]:
            flash(
                "Invalid algorithm chosen. Please, select from the provided list of standard algorithms",
                "error",
            )
            return render_template("add_secret.html"), 403

        if digits not in ["6", "7", "8"]:
            flash("Invalid OTP number of digits", "error")
            return render_template("add_secret.html"), 403

        if period not in ["15", "30", "60"]:
            flash("Invalid period", "error")
            return render_template("add_secret.html"), 403

        try:
            counter = int(counter)
        except ValueError:
            flash("Invalid counter", "error")
            return render_template("add_secret.html"), 403

        new_secret = {
            "id": uuid.uuid4().hex,
            "issuer": issuer,
            "account": account,
            "secret_key": secret,
            "otp_type": otp_type,
            "algorithm": algorithm,
            "digits": digits,
            "period": period,
            "counter": counter,
        }

        session["s"].append(new_secret)

        save_updated_secrets()

        flash("Secret added successfully", "success")
        return redirect("/")
    elif request.method == "GET":
        return render_template("add_secret.html")


@app.route("/next_counter", methods=["POST"])
@login_required
def next_counter():
    secret_id = request.form.get("id")
    count = request.form.get("count")

    print_c(session["s"])
    print_c(secret_id)

    if not secret_id or not count:
        flash("Missing required fields", "error"), 403
        return redirect("/")

    try:
        count = int(count)
    except ValueError:
        flash("Invalid counter", "error")
        return redirect("/")
    if count < 0:
        flash("Counter cannot be negative", "error")
        return redirect("/")

    if count % 1 != 0:
        flash("Counter must be an integer", "error")
        return redirect("/")
    for secret in session["s"]:
        if secret["id"] == secret_id:
            secret["counter"] = count
            save_updated_secrets()
            flash("Counter updated successfully", "success")
            return redirect("/")
    else:
        flash("Secret not found", "error")
        return redirect("/")


def save_updated_secrets(password=""):
    user_data = db.execute(
        "SELECT * FROM users WHERE id = :user_id;", user_id=session["user_id"]
    )
    if password == "":
        password = decrypt(session["p"], str(user_data[0]["s"]))

    new_encrypted_secrets = encrypt_secrets(
        user_data[0]["username"], password, str(session["s"])
    )

    db.execute(
        "UPDATE users SET s = :s WHERE id = :user_id;",
        user_id=session["user_id"],
        s=new_encrypted_secrets,
    )

    session["p"] = encrypt(password, str(new_encrypted_secrets))


@app.route("/delete_secret", methods=["POST"])
@login_required
def delete_secret():
    secret_id = request.form.get("id")
    if not secret_id:
        flash("Missing required fields", "error"), 403
        return redirect("/")
    for secret in session["s"]:
        if secret["id"] == secret_id:
            session["s"].remove(secret)
            save_updated_secrets()
            flash("Secret deleted successfully", "success")
            return redirect("/")
    else:
        flash("Secret not found", "error")
        return redirect("/")


@app.route("/account", methods=["GET"])
@login_required
def account():
    rows = db.execute(
        "SELECT * FROM users WHERE id = :user_id;", user_id=session["user_id"]
    )
    return render_template("account.html", username=rows[0]["username"])


@app.route("/change_username", methods=["POST"])
@login_required
def change_username():
    username = request.form.get("username")
    if not username:
        flash("Missing required fields", "error"), 403
        return redirect("/account")

    if not re.compile("^[A-Za-z][A-Za-z0-9_]{4,}$").match(username):
        flash(
            "Username should be: 5+ characters, and contains only characters and digits and underscores",
            "error",
        ), 403
        return redirect("/account")

    db.execute(
        "UPDATE users SET username = :username WHERE id = :user_id;",
        username=username,
        user_id=session["user_id"],
    )

    flash("Username changed successfully", "success")
    return redirect("/account")


@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_new_password")
    if not old_password or not new_password or not confirm_password:
        flash(
            "Please, fill in the passwords in order to change the old password", "error"
        ), 403
        return redirect("/account")

    userdata = db.execute(
        "SELECT * FROM users WHERE id = :user_id;", user_id=session["user_id"]
    )

    curr_password = decrypt(session["p"], str(userdata[0]["s"]))

    if curr_password != old_password:
        flash("Old password is incorrect", "error"), 403
        return redirect("/account")

    if new_password != confirm_password:
        flash("Passwords do not match", "error"), 403
        return redirect("/account")

    save_updated_secrets(new_password)

    flash("Password changed successfully", "success")
    return redirect("/account")

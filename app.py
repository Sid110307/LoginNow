#!/usr/bin/env python3

import base64
import logging
import os

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

AUTH_FILE = ".sid-auth"
USERS_FILE = ".sid-users"


@app.route("/favicon.ico")
def favicon():
    return app.send_static_file("favicon.ico")


@app.route("/", methods = ["GET"])
def root():
    if session.get("username") and session.get("password"):
        return redirect(url_for("home"))
    else:
        return render_template("register.html")


@app.route("/register", methods = ["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    if not username or not password:
        return jsonify({"error": "Please enter a username and password."}), 400

    if not os.path.isfile(AUTH_FILE):
        open(AUTH_FILE, "w").close()

    with open(AUTH_FILE, "r") as f:
        for line in f:
            user, pw = line.split(":")
            if user == username:
                return jsonify({"error": "Username is already taken."}), 400

    hashed_pw = generate_password_hash(
        str(base64.b64encode(username.encode("utf-8")) + base64.b64encode(password.encode("utf-8"))))
    with open(AUTH_FILE, "a") as file:
        file.write(f"{username}:{hashed_pw}\n")

    return redirect(url_for("login_page"))


@app.route("/login", methods = ["GET"])
def login_page():
    if session.get("username") and session.get("password"):
        return redirect(url_for("home"))
    else:
        return render_template("login.html")


@app.route("/loginForm", methods = ["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    if not username or not password:
        return jsonify({"error": "Please enter a username and password."}), 400

    with open(AUTH_FILE, "r") as file:
        for line in file:
            user, pw = line.split(":")
            if user == username:
                if check_password_hash(pw, str(base64.b64encode(username.encode("utf-8")) + base64.b64encode(
                        password.encode("utf-8")))):
                    session["username"] = username
                    session["password"] = password
                    return redirect(url_for("home"))
                else:
                    return jsonify({"error": "Incorrect password."}), 400


@app.route("/home")
def home():
    if session.get("username") and session.get("password"):
        return render_template("home.html", user = session["username"])
    else:
        return redirect(url_for("login_page"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/saveUser", methods = ["POST"])
def save_user():
    name = request.form["name"]
    email = request.form["email"]
    password = request.form["password"]

    if not name or not email or not password:
        return jsonify({"error": "Please enter a name, email, and password."}), 400

    hashed_pw = generate_password_hash(
        str(base64.b64encode(name.encode("utf-8")) + base64.b64encode(email.encode("utf-8")) + base64.b64encode(
            password.encode("utf-8"))))
    with open(USERS_FILE, "a") as file:
        file.write(f"{name}:{email}:{hashed_pw}\n")

    return redirect(url_for("home"))


@app.route("/getUsers", methods = ["GET"])
def get_users():
    if session.get("username") and session.get("password"):
        with open(USERS_FILE, "r") as file:
            users = file.readlines()
        return jsonify({"users": users})
    else:
        return redirect(url_for("login_page"))


@app.route("/deleteUser", methods = ["POST"])
def delete_user():
    if session.get("username") and session.get("password"):
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        if not name or not email or not password:
            return jsonify({"error": "Please enter a name, email, and password."}), 400

        with open(USERS_FILE, "r") as file:
            users = file.readlines()

        with open(USERS_FILE, "w") as file:
            for user in users:
                if user.split(":")[0] != name and user.split(":")[1] != email and user.split(":")[2] != password:
                    file.write(user)
        return redirect(url_for("home"))
    else:
        return redirect(url_for("login_page"))


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.run(debug = True)

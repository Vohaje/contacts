import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from sqlalchemy import except_
from werkzeug.security import check_password_hash, generate_password_hash
import datetime


from helpers import apology


app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


db = SQL("sqlite:///contact.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/notes", methods=["GET", "POST"])
def notes():
    #create and add note
    if request.method == "POST":
        user_id = session["user_id"]
        title = request.form.get("title")
        text = request.form.get("text")

        db.execute("INSERT INTO notes (user_id, title, text) VALUES(?, ?, ?)",
                   user_id, title, text)

        return redirect("/note")

    else:
        return render_template("notes.html")


@app.route("/note")
def note():
    #show all notes
    user_id = session["user_id"]
    notebooks = db.execute(
        "SELECT * FROM notes WHERE user_id = ? ORDER BY date", user_id)
    return render_template("note.html", notebooks=notebooks)


@app.route("/text", methods=["GET", "POST"])
def text():
    #more details about the selected note
    id = request.form.get("id")
    if request.method == "POST":
        title = db.execute("SELECT title FROM notes WHERE id = ?", id)[
            0]['title']
        text = db.execute("SELECT text FROM notes WHERE id = ?", id)[0]['text']
        date = db.execute("SELECT date FROM notes WHERE id = ?", id)[0]['date']
        return render_template("text.html", title=title, text=text, date=date)

    else:
        redirect("/note")


@app.route("/delete", methods=["POST"])
def delete_text():
    #delete selected note
    id = request.form.get("id")
    try:
        db.execute("DELETE FROM notes WHERE id = ?", id)
        return redirect("/note")
    except:
        return apology("Sorry")


@app.route("/friends")
def friends():
    #show all friends from db
    user_id = session["user_id"]
    friends = db.execute(
        "SELECT * FROM friends WHERE user_id = ? ORDER BY name", user_id)
    return render_template("friends.html", friends=friends)


@app.route("/add", methods=["GET", "POST"])
def add():
    #add new contact in my db
    if request.method == "POST":
        user_id = session["user_id"]
        name = request.form.get("name")
        birth = request.form.get("birth")
        phone = request.form.get("phone")
        email = request.form.get("email")

        db.execute("INSERT INTO friends (user_id, name, birth, phone, email) VALUES(?, ?, ?, ?, ?)",
                   user_id, name, birth, phone, email)

        return redirect("/friends")

    else:
        return render_template("add.html")


@app.route("/del", methods=["POST"])
def delete():
    #delete friends from db
    id = request.form.get("id")
    if id:
        db.execute("DELETE FROM friends WHERE id = ?", id)
    return redirect("/friends")


@app.route("/register", methods=["GET", "POST"])
def register():
    #register new user
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Username is required!")

        elif not password:
            return apology("Password is required!")

        elif not confirmation:
            return apology("Confirmation is required!")

        if password != confirmation:
            return apology("Password do dot match")

        hash = generate_password_hash(password)

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 0:
            apology("username already exists")

        db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    #Log user in

    session.clear()

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]

        return redirect("/note")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    return redirect("/")


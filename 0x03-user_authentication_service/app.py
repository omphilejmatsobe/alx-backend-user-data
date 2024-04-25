#!/usr/bin/env python3

"""
Module that operates a Flask app
"""

from flask import Flask, abort, jsonify, request, redirect, url_for
from auth import Auth

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True
AUTH = Auth()


@app.route("/")
def home() -> str:
    """ Home endpoint
        Return:
            - Logout message JSON represented
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/sessions", methods=["POST"])
def login():
    """
    Respond to the POST /sessions route
    """

    email = request.form.get("email")
    password = request.form.get("password")
    if not AUTH.valid_login(email, password):
        abort(401)
    _id = AUTH.create_session(email)
    res = jsonify({"email": email, "message": "logged in"})
    res.set_cookie("session_id", _id)
    return response


@app.route("/sessions", methods=["DELETE"])
def logout():
    """
    Responds to the DELETE /sessions route
    """

    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect(url_for("home"))


@app.route("/users", methods=["POST"])
def users():
    """
    implements the POST /users route
    """

    email = request.form.get("email")
    password = request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/profile")
def profile() -> str:
    """
    User profile endpoint that responds to the GET /profile route
    """

    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    return jsonify({"email": user.email})


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token() -> str:
    """
    Takes an email string argument and returns a string
    """

    email = request.form.get("email")
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token})


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """ Password update endpoint tha responds
    to the POST /reset_password route
    """

    email = request.form.get("email")
    new_pass = request.form.get("new_password")
    reset_token = request.form.get("reset_token")

    try:
        AUTH.update_pass(reset_token, new_pass)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "message": "Password updated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")

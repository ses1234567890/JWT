"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required

api = Blueprint('api', __name__)


@api.route('/register', methods=['POST'])
def user_register():
    body_email = request.json.get("email")
    body_password = request.json.get("password")

    if not body_email or not body_password:
        return jsonify({"response": "Email, and password are required."}), 300

    new_user = User(email=body_email, password=body_password, is_active=True)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"response": "User registered successfully"}), 200

@api.route('/login', methods=['POST'])
def user_login():
    body_email = request.json.get("email")
    body_password = request.json.get("password")
    user = User.query.filter_by(email=body_email).first()
    if user is None:
        return jsonify({"response": "Invalid username or password."}), 401
    token = create_access_token(identity=user.id)
    return jsonify({"response": "Hola", "token": token}), 200
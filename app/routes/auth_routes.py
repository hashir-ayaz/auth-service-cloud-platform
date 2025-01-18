import jwt
import datetime
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from app.models.user import User
from app import db

# Define the Blueprint
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# Secret key for signing tokens (should be stored in environment variables in production)
SECRET_KEY = "yummysecret"  # Replace with an environment variable


def generate_token(user_id):
    """
    Generate a JWT token for the given user ID.
    """
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow()
        + datetime.timedelta(hours=1),  # Token expiration
        "iat": datetime.datetime.utcnow(),  # Issued at
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# Login route
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    # Validate input
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Query the database for the user by email
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        token = generate_token(user.id)
        return jsonify({"message": "Login successful", "token": token}), 200

    return jsonify({"error": "Invalid credentials"}), 401


# Signup route
@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    # Validate input
    if not email or not username or not password:
        return jsonify({"error": "Email, username, and password are required"}), 400

    # Check if the email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Email already exists"}), 409

    # Hash the password
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

    # Create a new user
    new_user = User(email=email, username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    # Generate a token for the new user
    token = generate_token(new_user.id)

    return (
        jsonify(
            {"message": f"User {username} registered successfully", "token": token}
        ),
        201,
    )

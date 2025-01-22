import jwt as pyjwt
import datetime
import logging
from flask import Blueprint, request, jsonify, make_response, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from app.models.user import User
from app import db
from dotenv import load_dotenv
import os

load_dotenv()


# Define the Blueprint
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# Secret key for signing tokens (should be stored in environment variables in production)
SECRET_KEY = os.environ.get("SECRET_KEY")  # Replace with an environment variable

# Fallback logger for use outside app context
logger = logging.getLogger(__name__)


def generate_token(user_id):
    """
    Generate a JWT token for the given user ID.
    """
    try:
        payload = {
            "user_id": user_id,
            "exp": datetime.datetime.utcnow()
            + datetime.timedelta(hours=1),  # Token expiration
            "iat": datetime.datetime.utcnow(),  # Issued at
        }
        token = pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")
        logger.info(f"Token generated for user ID: {user_id}")
        return token
    except Exception as e:
        logger.error(f"Failed to generate token for user ID {user_id}: {str(e)}")
        raise


# Login route
@auth_bp.route("/login", methods=["POST"])
def login():
    current_app.logger.info("Login endpoint hit")
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        current_app.logger.warning("Login failed: Missing email or password")
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        current_app.logger.info(f"User {email} logged in successfully")
        token = generate_token(user.id)

        # Set the JWT as a cookie
        response = make_response(
            jsonify({"message": "Login successful", "token": token}), 200
        )
        response.set_cookie("jwt", token, httponly=True, secure=True, samesite="Strict")
        return response

    current_app.logger.warning(f"Login failed: Invalid credentials for email {email}")
    return jsonify({"error": "Invalid credentials"}), 401


# Signup route
@auth_bp.route("/signup", methods=["POST"])
def signup():
    current_app.logger.info("Signup endpoint hit")
    data = request.get_json()
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if not email or not username or not password:
        current_app.logger.warning("Signup failed: Missing required fields")
        return jsonify({"error": "Email, username, and password are required"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        current_app.logger.warning(f"Signup failed: Email {email} already exists")
        return jsonify({"error": "Email already exists"}), 409

    try:
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(email=email, username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        token = generate_token(new_user.id)
        current_app.logger.info(f"User {username} registered successfully")

        response = make_response(
            jsonify(
                {"message": f"User {username} registered successfully", "token": token}
            ),
            201,
        )
        response.set_cookie("jwt", token, httponly=True, secure=True, samesite="Strict")
        return response
    except Exception as e:
        current_app.logger.error(f"Signup failed for {email}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


# Logout route
@auth_bp.route("/logout", methods=["POST"])
def logout():
    current_app.logger.info("Logout endpoint hit")
    response = make_response(jsonify({"message": "Logged out successfully"}), 200)
    response.set_cookie(
        "jwt", "", httponly=True, secure=True, samesite="Strict", expires=0
    )
    current_app.logger.info("User logged out successfully")
    return response


# Token validation route
@auth_bp.route("/validate-token", methods=["POST"])
def validate_token():
    """
    Validate the provided JWT and return decoded user information.
    """
    current_app.logger.info("Validate token endpoint hit")
    data = request.get_json()
    token = data.get("token")

    current_app.logger.info(f"Token received: {token}")

    if not token:
        current_app.logger.warning("Token validation failed: Missing token")
        return jsonify({"error": "Token is required"}), 400

    try:
        # Decode the token
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        current_app.logger.info(f"Token decoded: {decoded_token}")
        user_id = decoded_token.get("user_id")
        current_app.logger.info(f"Token decoded successfully for user ID: {user_id}")

        # Verify that the user exists in the database
        user = User.query.get(user_id)
        if not user:
            current_app.logger.warning(
                f"Token validation failed: User with ID {user_id} not found"
            )
            return jsonify({"error": "Invalid token: user not found"}), 401

        current_app.logger.info(f"Token is valid for user ID: {user_id}")
        return (
            jsonify(
                {
                    "message": "Token is valid",
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "username": user.username,
                    },
                }
            ),
            200,
        )

    except jwt.ExpiredSignatureError:
        current_app.logger.warning("Token validation failed: Token has expired")
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        current_app.logger.warning("Token validation failed: Invalid token")
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        current_app.logger.error(f"Unexpected error during token validation: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

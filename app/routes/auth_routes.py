from flask import Blueprint, request, jsonify

# Define the Blueprint
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# Login route
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Replace with actual authentication logic
    if username == "admin" and password == "password":
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"error": "Invalid credentials"}), 401


# Signup route
@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Replace with actual user creation logic
    return jsonify({"message": f"User {username} registered successfully"}), 201

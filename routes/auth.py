from flask import Blueprint, request, jsonify

# Create a Blueprint for authentication
auth_bp = Blueprint("auth", __name__)

# In-memory user store (replace with a database in production)
users = {}


@auth_bp.route("/signup", methods=["POST"])
def signup():
    """
    Handle user signup.
    Expects JSON with 'username' and 'password'.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    if username in users:
        return jsonify({"error": "Username already exists."}), 409

    # Store the user (in a real app, hash the password before storing)
    users[username] = password
    return jsonify({"message": "User registered successfully!"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Handle user login.
    Expects JSON with 'username' and 'password'.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    # Validate user credentials
    if username not in users or users[username] != password:
        return jsonify({"error": "Invalid username or password."}), 401

    return jsonify({"message": "Login successful!"}), 200

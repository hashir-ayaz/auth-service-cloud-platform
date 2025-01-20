from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
import os

import logging

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)

    # Enable CORS globally

    # Enable CORS globally
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": [
                    os.getenv("FRONTEND_URL", "http://localhost:5173"),
                    "http://localhost:5001",  # Add localhost:5001
                ]
            },
        },
        supports_credentials=True,
    )

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],  # Logs to the console
    )
    app.logger.info("Logging is configured.")
    # PostgreSQL configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "postgresql://flaskuser:flaskpassword@localhost:5432/flaskdb"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize extensions
    db.init_app(app)

    # Register Blueprints
    from .routes.auth_routes import auth_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")

    return app

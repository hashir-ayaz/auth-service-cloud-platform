from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)

    # PostgreSQL configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "postgresql://flaskuser:flaskpassword@localhost:5432/flaskdb"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize extensions
    db.init_app(app)

    # Register Blueprints
    from .routes.auth_routes import auth_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")

    return app

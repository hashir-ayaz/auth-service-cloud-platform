from flask import Flask


def create_app():
    app = Flask(__name__)

    # Configuration (if any)
    # app.config["SECRET_KEY"] = (
    #     "your_secret_key"  # Replace with an environment variable in production
    # )

    # Register Blueprints
    from .routes.auth_routes import auth_bp

    app.register_blueprint(auth_bp)

    return app

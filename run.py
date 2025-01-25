from app import create_app, db
from app.models.user import User
from sqlalchemy.exc import OperationalError

app = create_app()


def create_tables():
    try:
        with app.app_context():
            db.create_all()
            print("Tables created successfully.")
    except OperationalError as e:
        print("Error creating tables: Could not connect to the database.")
        print(f"Details: {e}")
        # Optionally, you can log the error or retry connecting
    except Exception as e:
        print("An unexpected error occurred while creating tables.")
        print(f"Details: {e}")



if __name__ == "__main__":
    create_tables()
    app.run(debug=True, port=5000, host="0.0.0.0")

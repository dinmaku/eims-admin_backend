import pytest
from werkzeug.security import generate_password_hash
from app import create_app, db
import app.models as model_module

@pytest.fixture
def app():
    # Create test app with testing config
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        # any other settings your app needs to boot in tests
    }
    app = create_app(test_config)

    # create DB tables and a test user
    with app.app_context():
        db.create_all()

        # create a user that the login endpoint expects
        # adapt field names to your Users model (email/password_hash/user_id/etc.)
        test_user = Users(
            email="user@example.com",
            # assume your model uses `password_hash` — adapt if necessary
            password_hash=generate_password_hash("correct-password")
        )
        db.session.add(test_user)
        db.session.commit()

    yield app

    # teardown
    with app.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()
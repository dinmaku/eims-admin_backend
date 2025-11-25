# tests/test_sql_injection.py
import pytest
import time

# import from the app package (db.py lives in app/)
from app.db import get_db_connection
import app.models as model_module   # model_module.check_user & model_module.hash_password

TEST_EMAIL = "test_sql_inject@example.com"
TEST_PASSWORD = "correct-password-123"
TEST_USERTYPE = "Admin"

@pytest.fixture(scope="function")
def create_test_user():
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed = model_module.hash_password(TEST_PASSWORD)

    try:
        cursor.execute(
            "INSERT INTO users (email, password, user_type) VALUES (%s, %s, %s)",
            (TEST_EMAIL, hashed, TEST_USERTYPE)
        )
        conn.commit()
        yield {"email": TEST_EMAIL, "password": TEST_PASSWORD}
    finally:
        try:
            cursor.execute("DELETE FROM users WHERE email = %s", (TEST_EMAIL,))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
        cursor.close()
        conn.close()

def test_sql_injection_login(create_test_user):
    email = create_test_user["email"]

    # 1) attempt with classic SQLi payload
    injected_password = "' OR '1'='1"
    ok, user_type = model_module.check_user(email, injected_password)
    assert ok is False, "SQLi payload should NOT authenticate"
    assert user_type is None

    time.sleep(0.05)

    # 2) attempt with correct password
    ok2, user_type2 = model_module.check_user(email, create_test_user["password"])
    assert ok2 is True, "Correct password should authenticate"
    assert user_type2 == TEST_USERTYPE
import json
from app import create_app  # import your Flask app instance

def test_sql_injection_login():
    client = app.test_client()
    resp = client.post("/login",
                   data=json.dumps({
                       "email": "user@example.com",
                       "password": "' OR '1'='1"
                   }),
                   content_type="application/json")
    assert resp.status_code == 401

import pytest
from server import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_jwks(client):
    response = client.get('/jwks')
    assert response.status_code == 200
    data = response.get_json()
    assert "keys" in data  # Check keys are in response

def test_auth(client):
    response = client.post('/auth')
    assert response.status_code == 200
    data = response.get_json()
    assert "token" in data  # Check token in response

def test_auth_expired(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200 or response.status_code == 400
    data = response.get_json()
    if response.status_code == 200:
        assert "token" in data
    else:
        assert "error" in data

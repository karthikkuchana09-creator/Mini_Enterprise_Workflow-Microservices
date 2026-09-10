from app.tests.conftest import register_individual


def test_get_me(client):
    data = register_individual(client, "me@example.com")
    access = data["access_token"]
    r = client.get("/users/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    assert r.json()["email"] == "me@example.com"
    assert r.json()["status"] == "active"


def test_get_me_requires_auth(client):
    r = client.get("/users/me")
    assert r.status_code == 401


def test_update_profile(client):
    data = register_individual(client, "prof@example.com")
    access = data["access_token"]
    r = client.patch(
        "/users/me",
        headers={"Authorization": f"Bearer {access}"},
        json={"phone": "555-1111", "bio": "hello"},
    )
    assert r.status_code == 200


def test_me_not_active_rejected(client):
    client.post(
        "/auth/register/individual",
        json={"email": "ia@example.com", "password": "StrongPass1!", "full_name": "A"},
    )
    r = client.post("/auth/login", json={"email": "ia@example.com", "password": "StrongPass1!"})
    assert r.status_code == 403

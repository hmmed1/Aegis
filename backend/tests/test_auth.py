"""Tests for the authentication flow."""


def test_root_serves_login_page_when_logged_out(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "login" in response.text.lower()


def test_login_with_correct_credentials_sets_session_cookie(client):
    response = client.post(
        "/login",
        json={"username": "testuser", "password": "testpass"},
    )
    assert response.status_code == 200
    assert "session" in response.cookies


def test_login_with_wrong_password_returns_401(client):
    response = client.post(
        "/login",
        json={"username": "testuser", "password": "WRONG"},
    )
    assert response.status_code == 401


def test_login_with_wrong_username_returns_401(client):
    response = client.post(
        "/login",
        json={"username": "nobody", "password": "testpass"},
    )
    assert response.status_code == 401


def test_dashboard_redirects_when_not_logged_in(client):
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_dashboard_shows_html_when_logged_in(client):
    # Log in first, then access /dashboard.
    client.post("/login", json={"username": "testuser", "password": "testpass"})
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 200
    assert "html" in response.headers["content-type"].lower()
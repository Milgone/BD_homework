"""
Тесты для API трекера задач.

Покрывает:
- Аутентификацию
- CRUD операции для задач
- Фильтрацию задач
- Аналитику
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from main import app, get_db
from models import Base, Task, User, Category

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """Создать тестовую сессию БД."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """Создать тестовый клиент."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(client):
    """Создать тестового пользователя."""
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpass123",
        "full_name": "Test User",
    }
    response = client.post("/api/auth/register", json=user_data)
    assert response.status_code == 201
    return response.json(), user_data


@pytest.fixture
def auth_token(client, test_user):
    """Получить токен аутентификации."""
    _, user_data = test_user
    response = client.post(
        "/api/auth/login",
        json={"username": user_data["username"], "password": user_data["password"]},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
def auth_headers(auth_token):
    """Получить заголовки с токеном."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def test_category(client, auth_headers):
    """Создать тестовую категорию."""
    category_data = {"name": "Development", "description": "Development tasks"}
    response = client.post("/api/categories", json=category_data, headers=auth_headers)
    assert response.status_code == 201
    return response.json()


class TestAuthentication:
    """Тесты аутентификации."""

    def test_register_user(self, client):
        """Тест регистрации пользователя."""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "password123",
        }
        response = client.post("/api/auth/register", json=user_data)
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == user_data["username"]
        assert data["email"] == user_data["email"]
        assert "hashed_password" not in data

    def test_register_duplicate_user(self, client, test_user):
        """Тест регистрации дубликата пользователя."""
        _, user_data = test_user
        response = client.post("/api/auth/register", json=user_data)
        assert response.status_code == 400

    def test_login_success(self, client, test_user):
        """Тест успешного входа."""
        _, user_data = test_user
        response = client.post(
            "/api/auth/login",
            json={"username": user_data["username"], "password": user_data["password"]},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_login_wrong_password(self, client, test_user):
        """Тест входа с неверным паролем."""
        _, user_data = test_user
        response = client.post(
            "/api/auth/login",
            json={"username": user_data["username"], "password": "wrongpass"},
        )
        assert response.status_code == 401

    def test_protected_endpoint_without_token(self, client):
        """Тест доступа к защищенному endpoint без токена."""
        response = client.get("/api/tasks")
        assert response.status_code == 401

    def test_protected_endpoint_with_token(self, client, auth_headers):
        """Тест доступа к защищенному endpoint с токеном."""
        response = client.get("/api/tasks", headers=auth_headers)
        assert response.status_code == 200


class TestTaskCRUD:
    """Тесты CRUD операций для задач."""

    def test_create_task(self, client, auth_headers, test_category):
        """Тест создания задачи."""
        task_data = {
            "title": "Test Task",
            "description": "Test description",
            "status": "новая",
            "priority": 1,
            "category_id": test_category["id"],
        }
        response = client.post("/api/tasks", json=task_data, headers=auth_headers)
        assert response.status_code == 201
        data = response.json()
        assert data["title"] == task_data["title"]
        assert data["status"] == task_data["status"]
        assert "id" in data

    def test_create_task_invalid_status(self, client, auth_headers):
        """Тест создания задачи с неверным статусом."""
        task_data = {
            "title": "Test Task",
            "status": "invalid_status",
        }
        response = client.post("/api/tasks", json=task_data, headers=auth_headers)
        assert response.status_code == 400

    def test_get_task(self, client, auth_headers, test_category):
        """Тест получения задачи."""
        task_data = {
            "title": "Get Task",
            "description": "Test",
            "category_id": test_category["id"],
        }
        create_response = client.post("/api/tasks", json=task_data, headers=auth_headers)
        task_id = create_response.json()["id"]

        response = client.get(f"/api/tasks/{task_id}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == task_id
        assert data["title"] == task_data["title"]

    def test_get_nonexistent_task(self, client, auth_headers):
        """Тест получения несуществующей задачи."""
        response = client.get("/api/tasks/99999", headers=auth_headers)
        assert response.status_code == 404

    def test_list_tasks(self, client, auth_headers, test_category):
        """Тест получения списка задач."""
        for i in range(3):
            task_data = {
                "title": f"Task {i}",
                "category_id": test_category["id"],
            }
            client.post("/api/tasks", json=task_data, headers=auth_headers)

        response = client.get("/api/tasks", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

    def test_update_task(self, client, auth_headers, test_category):
        """Тест обновления задачи."""
        task_data = {
            "title": "Original Title",
            "category_id": test_category["id"],
        }
        create_response = client.post("/api/tasks", json=task_data, headers=auth_headers)
        task_id = create_response.json()["id"]

        update_data = {"title": "Updated Title", "status": "в работе"}
        response = client.put(f"/api/tasks/{task_id}", json=update_data, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == update_data["title"]
        assert data["status"] == update_data["status"]

    def test_delete_task(self, client, auth_headers, test_category):
        """Тест удаления задачи."""
        task_data = {
            "title": "Task to Delete",
            "category_id": test_category["id"],
        }
        create_response = client.post("/api/tasks", json=task_data, headers=auth_headers)
        task_id = create_response.json()["id"]

        response = client.delete(f"/api/tasks/{task_id}", headers=auth_headers)
        assert response.status_code == 204

        get_response = client.get(f"/api/tasks/{task_id}", headers=auth_headers)
        assert get_response.status_code == 404


class TestTaskFiltering:
    """Тесты фильтрации задач."""

    def test_filter_by_status(self, client, auth_headers, test_category):
        """Тест фильтрации по статусу."""
        client.post(
            "/api/tasks",
            json={"title": "New Task", "status": "новая", "category_id": test_category["id"]},
            headers=auth_headers,
        )
        client.post(
            "/api/tasks",
            json={"title": "In Progress Task", "status": "в работе", "category_id": test_category["id"]},
            headers=auth_headers,
        )

        response = client.get("/api/tasks?status=новая", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert all(task["status"] == "новая" for task in data)

    def test_filter_by_category(self, client, auth_headers, test_category):
        """Тест фильтрации по категории."""
        task_data = {
            "title": "Categorized Task",
            "category_id": test_category["id"],
        }
        client.post("/api/tasks", json=task_data, headers=auth_headers)

        response = client.get(f"/api/tasks?category_id={test_category['id']}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert all(task["category_id"] == test_category["id"] for task in data)

    def test_search_tasks(self, client, auth_headers, test_category):
        """Тест поиска задач."""
        client.post(
            "/api/tasks",
            json={"title": "Python Task", "category_id": test_category["id"]},
            headers=auth_headers,
        )
        client.post(
            "/api/tasks",
            json={"title": "JavaScript Task", "category_id": test_category["id"]},
            headers=auth_headers,
        )

        response = client.get("/api/tasks?search=Python", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert "Python" in data[0]["title"]


class TestAnalytics:
    """Тесты аналитики."""

    def test_get_statistics(self, client, auth_headers, test_category, db_session):
        """Тест получения статистики."""
        for status in ["новая", "в работе", "сделано"]:
            client.post(
                "/api/tasks",
                json={"title": f"Task {status}", "status": status, "category_id": test_category["id"]},
                headers=auth_headers,
            )

        response = client.get("/api/analytics/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "by_status" in data
        assert "by_category" in data
        assert "total_tasks" in data
        assert data["total_tasks"] == 3

    def test_visualize_analytics(self, client, auth_headers, test_category):
        """Тест визуализации аналитики."""
        for i in range(5):
            client.post(
                "/api/tasks",
                json={
                    "title": f"Task {i}",
                    "status": ["новая", "в работе", "сделано"][i % 3],
                    "category_id": test_category["id"],
                },
                headers=auth_headers,
            )

        response = client.get("/api/analytics/visualize", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "chart_path" in data
        assert "statistics" in data


class TestCategories:
    """Тесты для категорий."""

    def test_create_category(self, client, auth_headers):
        """Тест создания категории."""
        category_data = {"name": "Testing", "description": "Test category"}
        response = client.post("/api/categories", json=category_data, headers=auth_headers)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == category_data["name"]

    def test_list_categories(self, client, auth_headers):
        """Тест получения списка категорий."""
        for name in ["Category 1", "Category 2"]:
            client.post("/api/categories", json={"name": name}, headers=auth_headers)

        response = client.get("/api/categories", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 2


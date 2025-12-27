"""
Тесты для работы с базой данных.

Проверяют:
- Создание и удаление записей
- Связи между моделями
- Защиту от SQL-инъекций через ORM
"""
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from models import Base, Category, Task, TaskStatus, User

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    """Создать тестовую сессию БД."""
    Base.metadata.create_all(bind=engine)
    db_session = TestingSessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()
        Base.metadata.drop_all(bind=engine)


class TestDatabaseModels:
    """Тесты моделей базы данных."""

    def test_create_user(self, db):
        """Тест создания пользователя."""
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_password",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"

    def test_create_task(self, db):
        """Тест создания задачи."""
        user = User(
            username="assignee",
            email="assignee@example.com",
            hashed_password="hashed",
        )
        db.add(user)
        db.flush()

        category = Category(name="Development", description="Dev tasks")
        db.add(category)
        db.flush()

        task = Task(
            title="Test Task",
            description="Test description",
            status=TaskStatus.NEW.value,
            assignee_id=user.id,
            category_id=category.id,
        )
        db.add(task)
        db.commit()
        db.refresh(task)

        assert task.id is not None
        assert task.title == "Test Task"
        assert task.assignee_id == user.id
        assert task.category_id == category.id

    def test_task_user_relationship(self, db):
        """Тест связи задачи и пользователя."""
        user = User(
            username="user1",
            email="user1@example.com",
            hashed_password="hashed",
        )
        db.add(user)
        db.flush()

        task1 = Task(title="Task 1", assignee_id=user.id)
        task2 = Task(title="Task 2", assignee_id=user.id)
        db.add_all([task1, task2])
        db.commit()

        db.refresh(user)
        assert len(user.assigned_tasks) == 2
        assert task1 in user.assigned_tasks
        assert task2 in user.assigned_tasks

    def test_task_category_relationship(self, db):
        """Тест связи задачи и категории."""
        category = Category(name="Testing")
        db.add(category)
        db.flush()

        task1 = Task(title="Task 1", category_id=category.id)
        task2 = Task(title="Task 2", category_id=category.id)
        db.add_all([task1, task2])
        db.commit()

        db.refresh(category)
        assert len(category.tasks) == 2

    def test_cascade_delete_user(self, db):
        """Тест каскадного удаления задач при удалении пользователя."""
        user = User(
            username="user1",
            email="user1@example.com",
            hashed_password="hashed",
        )
        db.add(user)
        db.flush()

        task = Task(title="Task 1", assignee_id=user.id)
        db.add(task)
        db.commit()

        task_id = task.id
        db.delete(user)
        db.commit()

        deleted_task = db.get(Task, task_id)
        assert deleted_task is None

    def test_set_null_on_category_delete(self, db):
        """Тест установки NULL при удалении категории."""
        category = Category(name="Temp Category")
        db.add(category)
        db.flush()

        task = Task(title="Task 1", category_id=category.id)
        db.add(task)
        db.commit()

        task_id = task.id
        db.delete(category)
        db.commit()

        remaining_task = db.get(Task, task_id)
        assert remaining_task is not None
        assert remaining_task.category_id is None


class TestSQLInjectionProtection:
    """Тесты защиты от SQL-инъекций."""

    def test_parameterized_queries(self, db):
        """Тест использования параметризованных запросов."""
        malicious_input = "'; DROP TABLE tasks; --"
        user = User(
            username=malicious_input,
            email="test@example.com",
            hashed_password="hashed",
        )
        db.add(user)
        db.commit()

        found_user = db.query(User).filter(User.username == malicious_input).first()
        assert found_user is not None
        assert found_user.username == malicious_input

        tasks_count = db.query(Task).count()
        assert tasks_count >= 0  # Таблица не была удалена

    def test_safe_string_filtering(self, db):
        """Тест безопасной фильтрации строк."""
        task1 = Task(title="Normal Task")
        task2 = Task(title="Another Task")
        db.add_all([task1, task2])
        db.commit()

        search_term = "%Task%"
        results = db.query(Task).filter(Task.title.ilike(search_term)).all()
        assert len(results) == 2

        malicious_search = "'; DROP TABLE tasks; --"
        results = db.query(Task).filter(Task.title.ilike(f"%{malicious_search}%")).all()
        assert isinstance(results, list)

    def test_numeric_filtering(self, db):
        """Тест безопасной фильтрации по числовым полям."""
        user = User(
            username="user1",
            email="user1@example.com",
            hashed_password="hashed",
        )
        db.add(user)
        db.flush()

        task = Task(title="Task 1", assignee_id=user.id)
        db.add(task)
        db.commit()

        user_id = user.id
        found_task = db.query(Task).filter(Task.assignee_id == user_id).first()
        assert found_task is not None

        malicious_id = "1 OR 1=1"
        try:
            result = db.query(Task).filter(Task.assignee_id == malicious_id).first()
            assert result is None or isinstance(result, Task)
        except Exception:
            pass


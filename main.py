"""
FastAPI приложение для трекера задач.

Реализует:
- CRUD операции для задач
- Фильтрацию задач
- Аналитику и визуализацию
- Аутентификацию и авторизацию
"""
import os
from datetime import datetime, timedelta
from typing import List, Optional

import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
import bcrypt
from pydantic import BaseModel, EmailStr
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, joinedload

if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = "postgresql://artemkondra@localhost:5432/task_tracker"

from models import Base, Category, SessionLocal, Task, TaskStatus, User, engine

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

app = FastAPI(
    title="Task Tracker API",
    description="API для управления задачами с аналитикой и визуализацией",
    version="1.0.0",
)

Base.metadata.create_all(bind=engine)
class UserCreate(BaseModel):
    """Схема для создания пользователя."""

    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserResponse(BaseModel):
    """Схема ответа пользователя."""

    id: int
    username: str
    email: str
    full_name: Optional[str]

    model_config = {"from_attributes": True}


class TaskCreate(BaseModel):
    """Схема для создания задачи."""

    title: str
    description: Optional[str] = None
    status: str = TaskStatus.NEW.value
    priority: int = 0
    assignee_id: Optional[int] = None
    category_id: Optional[int] = None
    due_date: Optional[datetime] = None


class TaskUpdate(BaseModel):
    """Схема для обновления задачи."""

    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[int] = None
    assignee_id: Optional[int] = None
    category_id: Optional[int] = None
    due_date: Optional[datetime] = None


class TaskResponse(BaseModel):
    """Схема ответа задачи."""

    id: int
    title: str
    description: Optional[str]
    status: str
    priority: int
    assignee_id: Optional[int]
    category_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    due_date: Optional[datetime]
    assignee: Optional[UserResponse] = None
    category_name: Optional[str] = None

    model_config = {"from_attributes": True}


class CategoryCreate(BaseModel):
    """Схема для создания категории."""

    name: str
    description: Optional[str] = None


class CategoryResponse(BaseModel):
    """Схема ответа категории."""

    id: int
    name: str
    description: Optional[str]

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    """Схема для входа."""

    username: str
    password: str


class TokenResponse(BaseModel):
    """Схема ответа токена."""

    access_token: str
    token_type: str = "bearer"


def get_db() -> Session:
    """Получить сессию БД."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверить пароль."""
    try:
        password_bytes = plain_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Хешировать пароль."""
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Создать JWT токен."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db),
) -> User:
    """Получить текущего пользователя из токена."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. Please check your token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if not credentials:
            raise credentials_exception
        token = credentials.credentials
        if not token:
            raise credentials_exception
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token. Please login again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication error: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@app.post("/api/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Регистрация нового пользователя."""
    existing = db.execute(
        select(User).where(
            or_(User.username == user_data.username, User.email == user_data.email)
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    hashed_password = get_password_hash(user_data.password)
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        full_name=user_data.full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/auth/login", response_model=TokenResponse)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    """Вход пользователя."""
    user = db.execute(select(User).where(User.username == login_data.username)).scalar_one_or_none()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/categories", response_model=CategoryResponse, status_code=status.HTTP_201_CREATED)
def create_category(
    category_data: CategoryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Создать категорию."""
    existing = db.execute(select(Category).where(Category.name == category_data.name)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Category with this name already exists",
        )
    category = Category(name=category_data.name, description=category_data.description)
    db.add(category)
    db.commit()
    db.refresh(category)
    return category


@app.get("/api/categories", response_model=List[CategoryResponse])
def list_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Получить список категорий."""
    categories = db.execute(select(Category)).scalars().all()
    return categories


@app.post("/api/tasks", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
def create_task(
    task_data: TaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Создать задачу."""
    if task_data.status not in [s.value for s in TaskStatus]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Allowed: {[s.value for s in TaskStatus]}",
        )

    if task_data.assignee_id:
        assignee = db.get(User, task_data.assignee_id)
        if not assignee:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Assignee not found",
            )

    if task_data.category_id:
        category = db.get(Category, task_data.category_id)
        if not category:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Category not found",
            )

    task = Task(**task_data.model_dump())
    db.add(task)
    db.commit()
    db.refresh(task)
    db.refresh(task, ["assignee", "category"])
    response = TaskResponse.model_validate(task)
    if task.category:
        response.category_name = task.category.name
    return response


@app.get("/api/tasks", response_model=List[TaskResponse])
def list_tasks(
    status: Optional[str] = None,
    assignee_id: Optional[int] = None,
    category_id: Optional[int] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Получить список задач с фильтрацией."""
    query = select(Task).options(joinedload(Task.assignee), joinedload(Task.category))

    filters = []
    if status:
        filters.append(Task.status == status)
    if assignee_id:
        filters.append(Task.assignee_id == assignee_id)
    if category_id:
        filters.append(Task.category_id == category_id)
    if search:
        filters.append(
            or_(
                Task.title.ilike(f"%{search}%"),
                Task.description.ilike(f"%{search}%"),
            )
        )

    if filters:
        query = query.where(and_(*filters))

    query = query.order_by(Task.created_at.desc())
    tasks = db.execute(query).scalars().unique().all()

    result = []
    for task in tasks:
        response = TaskResponse.model_validate(task)
        if task.category:
            response.category_name = task.category.name
        result.append(response)
    return result


@app.get("/api/tasks/{task_id}", response_model=TaskResponse)
def get_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Получить задачу по ID."""
    task = db.execute(
        select(Task)
        .options(joinedload(Task.assignee), joinedload(Task.category))
        .where(Task.id == task_id)
    ).scalar_one_or_none()
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    response = TaskResponse.model_validate(task)
    if task.category:
        response.category_name = task.category.name
    return response


@app.put("/api/tasks/{task_id}", response_model=TaskResponse)
def update_task(
    task_id: int,
    task_data: TaskUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Обновить задачу."""
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )

    if task_data.status and task_data.status not in [s.value for s in TaskStatus]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Allowed: {[s.value for s in TaskStatus]}",
        )

    update_data = task_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(task, field, value)

    db.commit()
    db.refresh(task, ["assignee", "category"])
    response = TaskResponse.model_validate(task)
    if task.category:
        response.category_name = task.category.name
    return response


@app.delete("/api/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Удалить задачу."""
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    db.delete(task)
    db.commit()
    return None


@app.get("/api/analytics/stats")
def get_task_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Получить статистику по задачам."""
    status_stats = (
        db.query(Task.status, func.count(Task.id).label("count"))
        .group_by(Task.status)
        .all()
    )

    assignee_stats = (
        db.query(
            User.username,
            func.count(Task.id).label("count"),
        )
        .join(Task, User.id == Task.assignee_id, isouter=True)
        .group_by(User.id, User.username)
        .having(func.count(Task.id) > 0)
        .all()
    )

    category_stats = (
        db.query(
            Category.name,
            func.count(Task.id).label("count"),
        )
        .join(Task, Category.id == Task.category_id, isouter=True)
        .group_by(Category.id, Category.name)
        .having(func.count(Task.id) > 0)
        .all()
    )

    return {
        "by_status": {status: count for status, count in status_stats},
        "by_assignee": {username: count for username, count in assignee_stats},
        "by_category": {name: count for name, count in category_stats},
        "total_tasks": db.query(func.count(Task.id)).scalar(),
    }


@app.get("/api/analytics/visualize")
def visualize_analytics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Создать визуализацию аналитики."""
    tasks = db.query(Task).all()
    if not tasks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No tasks found for visualization",
        )

    df = pd.DataFrame(
        [
            {
                "id": t.id,
                "status": t.status,
                "assignee": t.assignee.username if t.assignee else "Unassigned",
                "category": t.category.name if t.category else "Uncategorized",
                "priority": t.priority,
                "created_at": t.created_at,
            }
            for t in tasks
        ]
    )

    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    fig.suptitle("Task Analytics Dashboard", fontsize=16)

    status_counts = df["status"].value_counts()
    axes[0, 0].bar(status_counts.index, status_counts.values, color="skyblue")
    axes[0, 0].set_title("Tasks by Status")
    axes[0, 0].set_ylabel("Count")
    axes[0, 0].tick_params(axis="x", rotation=45)

    assignee_counts = df["assignee"].value_counts().head(10)
    axes[0, 1].barh(assignee_counts.index, assignee_counts.values, color="lightgreen")
    axes[0, 1].set_title("Tasks by Assignee (Top 10)")
    axes[0, 1].set_xlabel("Count")

    category_counts = df["category"].value_counts()
    axes[1, 0].pie(
        category_counts.values,
        labels=category_counts.index,
        autopct="%1.1f%%",
        startangle=90,
    )
    axes[1, 0].set_title("Tasks by Category")

    priority_counts = df["priority"].value_counts().sort_index()
    axes[1, 1].bar(priority_counts.index, priority_counts.values, color="coral")
    axes[1, 1].set_title("Tasks by Priority")
    axes[1, 1].set_xlabel("Priority Level")
    axes[1, 1].set_ylabel("Count")

    plt.tight_layout()

    chart_path = "task_analytics.png"
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close()

    return {
        "message": "Visualization created successfully",
        "chart_path": chart_path,
        "statistics": {
            "total_tasks": len(df),
            "status_distribution": status_counts.to_dict(),
            "top_assignees": assignee_counts.head(5).to_dict(),
        },
    }


@app.get("/", response_class=HTMLResponse)
def root():
    """Главная страница приложения."""
    html_content = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Task Tracker API</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                max-width: 800px;
                width: 100%;
                padding: 40px;
            }
            h1 {
                color: #333;
                font-size: 2.5em;
                margin-bottom: 10px;
                text-align: center;
            }
            .subtitle {
                color: #666;
                text-align: center;
                margin-bottom: 30px;
                font-size: 1.1em;
            }
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }
            .feature {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                border-left: 4px solid #667eea;
            }
            .feature h3 {
                color: #667eea;
                margin-bottom: 10px;
            }
            .feature p {
                color: #666;
                font-size: 0.9em;
            }
            .links {
                display: flex;
                gap: 15px;
                justify-content: center;
                flex-wrap: wrap;
                margin-top: 30px;
            }
            .btn {
                display: inline-block;
                padding: 12px 30px;
                background: #667eea;
                color: white;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                transition: all 0.3s;
            }
            .btn:hover {
                background: #5568d3;
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            }
            .btn-secondary {
                background: #6c757d;
            }
            .btn-secondary:hover {
                background: #5a6268;
            }
            .version {
                text-align: center;
                color: #999;
                margin-top: 30px;
                font-size: 0.9em;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Task Tracker API</h1>
            <p class="subtitle">Система управления задачами с аналитикой и визуализацией</p>
            
            <div class="features">
                <div class="feature">
                    <h3>CRUD операции</h3>
                    <p>Полный набор операций для управления задачами</p>
                </div>
                <div class="feature">
                    <h3>Фильтрация</h3>
                    <p>Поиск и фильтрация по статусу, исполнителю, категории</p>
                </div>
                <div class="feature">
                    <h3>Аналитика</h3>
                    <p>Статистика и визуализация данных о задачах</p>
                </div>
                <div class="feature">
                    <h3>Безопасность</h3>
                    <p>JWT аутентификация и защита от SQL-инъекций</p>
                </div>
            </div>
            
            <div class="links">
                <a href="/docs" class="btn">Документация API</a>
                <a href="/redoc" class="btn btn-secondary">Альтернативная документация</a>
            </div>
            
            <div class="version">
                Версия 1.0.0
            </div>
        </div>
    </body>
    </html>
    """
    return html_content


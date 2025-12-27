#!/usr/bin/env python3

import os
from datetime import datetime, timedelta
import bcrypt

from models import Base, Category, SessionLocal, Task, TaskStatus, User, engine

def init_database():
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        if db.query(User).count() > 0:
            print("Данные уже есть в базе, пропускаем...")
            return
        
        print("Создаю тестовые данные...")
        
        users_data = [
            {"username": "admin", "email": "admin@example.com", "password": "admin123", "full_name": "Администратор"},
            {"username": "dev1", "email": "dev1@example.com", "password": "dev123", "full_name": "Разработчик 1"},
            {"username": "dev2", "email": "dev2@example.com", "password": "dev123", "full_name": "Разработчик 2"},
            {"username": "tester", "email": "tester@example.com", "password": "test123", "full_name": "Тестировщик"},
        ]
        
        users = []
        for u in users_data:
            hashed = bcrypt.hashpw(u["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user = User(
                username=u["username"],
                email=u["email"],
                hashed_password=hashed,
                full_name=u["full_name"]
            )
            db.add(user)
            users.append(user)
        
        db.commit()
        print(f"Создано пользователей: {len(users)}")
        
        categories_data = [
            {"name": "Development", "description": "Задачи разработки"},
            {"name": "Testing", "description": "Задачи тестирования"},
            {"name": "Documentation", "description": "Задачи документации"},
            {"name": "Bug Fix", "description": "Исправление ошибок"},
        ]
        
        categories = []
        for c in categories_data:
            cat = Category(name=c["name"], description=c["description"])
            db.add(cat)
            categories.append(cat)
        
        db.commit()
        print(f"Создано категорий: {len(categories)}")
        
        tasks_data = [
            {"title": "Реализовать API для задач", "description": "Создать REST API endpoints", "status": TaskStatus.DONE.value, "priority": 2, "assignee": users[1], "category": categories[0]},
            {"title": "Добавить фильтрацию задач", "description": "Реализовать фильтрацию по статусу", "status": TaskStatus.DONE.value, "priority": 2, "assignee": users[1], "category": categories[0]},
            {"title": "Написать тесты", "description": "Покрыть endpoints тестами", "status": TaskStatus.IN_PROGRESS.value, "priority": 1, "assignee": users[2], "category": categories[1]},
            {"title": "Создать аналитику", "description": "Добавить статистику и графики", "status": TaskStatus.IN_PROGRESS.value, "priority": 1, "assignee": users[1], "category": categories[0]},
            {"title": "Исправить баг с авторизацией", "description": "Проблема с токенами", "status": TaskStatus.NEW.value, "priority": 2, "assignee": users[2], "category": categories[3]},
            {"title": "Написать документацию", "description": "Создать README", "status": TaskStatus.NEW.value, "priority": 0, "assignee": users[3], "category": categories[2]},
        ]
        
        tasks = []
        for t in tasks_data:
            task = Task(
                title=t["title"],
                description=t["description"],
                status=t["status"],
                priority=t["priority"],
                assignee_id=t["assignee"].id if t["assignee"] else None,
                category_id=t["category"].id,
                due_date=datetime.utcnow() + timedelta(days=7)
            )
            db.add(task)
            tasks.append(task)
        
        db.commit()
        print(f"Создано задач: {len(tasks)}")
        
        print("\nГотово!")
        print("\nТестовые пользователи:")
        for u in users_data:
            print(f"  {u['username']} / {u['password']}")
            
    except Exception as e:
        db.rollback()
        print(f"Ошибка: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    init_database()

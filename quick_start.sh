#!/bin/bash

cd "$(dirname "$0")" || exit 1

echo "Запуск Task Tracker API"
echo ""

PYTHON_CMD=$(which python3 2>/dev/null || echo "python3")

echo "Проверка зависимостей..."
$PYTHON_CMD -c "import fastapi" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Устанавливаю зависимости..."
    $PYTHON_CMD -m pip install -r requirements.txt
fi

export DATABASE_URL="${DATABASE_URL:-postgresql://artemkondra@localhost:5432/task_tracker}"
export SECRET_KEY="${SECRET_KEY:-my-secret-key-123}"

echo "DATABASE_URL: $DATABASE_URL"
echo ""

echo "Проверка базы данных..."
if ! psql -lqt | cut -d \| -f 1 | grep -qw task_tracker; then
    echo "База данных 'task_tracker' не найдена!"
    echo "Создайте её: createdb task_tracker"
    exit 1
fi

echo "Применение миграций..."
alembic upgrade head

echo ""
echo "Запуск сервера на http://localhost:8000"
echo "Документация: http://localhost:8000/docs"
echo "Для остановки: Ctrl+C"
echo ""

$PYTHON_CMD -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

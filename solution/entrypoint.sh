#!/bin/bash

set -e

check_env_var() {
    if [ -z "${!1}" ]; then
        echo "Ошибка: Переменная окружения $1 не установлена."
        exit 1
    fi
}

DATE_UTC=$(date -u '+%Y-%m-%d %H:%M:%S')
export DATE_UTC

CURRENT_USER="Vadim-Khristenko"
export CURRENT_USER

echo "============================================"
echo "Application Startup"
echo "Date: ${DATE_UTC} UTC"
echo "User: ${CURRENT_USER}"
echo "============================================"

printenv > /app/.env
echo "Environment Configuration:"
echo "- Server: ${SERVER_ADDRESS:-Not Set}"
echo "- PostgreSQL:"
echo "  Host: ${POSTGRES_HOST:-Not Set}:${POSTGRES_PORT:-Not Set}"
echo "  Database: ${POSTGRES_DATABASE:-Not Set}"
echo "  Connection: ${POSTGRES_CONN:-Not Set}"
echo "  JDBC URL: ${POSTGRES_JDBC_URL:-Not Set}"
echo "- Redis: ${REDIS_HOST:-Not Set}:${REDIS_PORT:-Not Set}"
echo "- Antifraud: ${ANTIFRAUD_ADDRESS:-Not Set}"
echo "============================================"

check_env_var SERVER_ADDRESS
check_env_var POSTGRES_HOST
check_env_var POSTGRES_PORT
check_env_var POSTGRES_DATABASE
check_env_var REDIS_HOST
check_env_var REDIS_PORT
check_env_var ANTIFRAUD_ADDRESS

SERVER_HOST=$(echo ${SERVER_ADDRESS} | cut -d: -f1)
SERVER_PORT=$(echo ${SERVER_ADDRESS} | cut -d: -f2)
export SERVER_HOST=${SERVER_HOST}
export SERVER_PORT=${SERVER_PORT}

echo "Python Server"
echo "Server Host: ${SERVER_HOST}"
echo "Server Port: ${SERVER_PORT}"
echo "============================================"

if [ ! -f ./main.py ]; then
    echo "Ошибка: Файл main.py не найден."
    exit 1
fi

if [ ! -x ./main.py ]; then
    echo "Ошибка: Файл main.py не имеет прав на выполнение."
    chmod +x ./main.py || { echo "Не удалось установить права на выполнение."; exit 1; }
fi

START_TIME=$(date +%s)
python ./main.py || { echo "Ошибка: Не удалось запустить main.py"; exit 1; }
END_TIME=$(date +%s)

RUN_TIME=$((END_TIME - START_TIME))
echo "Время выполнения: ${RUN_TIME} секунд"
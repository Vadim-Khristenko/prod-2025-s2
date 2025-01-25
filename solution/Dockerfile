FROM python:3.12-alpine
WORKDIR /app

RUN apk add --no-cache bash

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN chmod 755 -R /app
RUN echo '#!/bin/bash' > entrypoint.sh && \
    echo 'set -e' >> entrypoint.sh && \
    echo 'check_env_var() {' >> entrypoint.sh && \
    echo '    if [ -z "${!1}" ]; then' >> entrypoint.sh && \
    echo '        echo "Ошибка: Переменная окружения $1 не установлена."' >> entrypoint.sh && \
    echo '        exit 1' >> entrypoint.sh && \
    echo '    fi' >> entrypoint.sh && \
    echo '}' >> entrypoint.sh && \
    echo 'DATE_UTC=$(date -u '\''+%Y-%m-%d %H:%M:%S'\'')' >> entrypoint.sh && \
    echo 'export DATE_UTC' >> entrypoint.sh && \
    echo 'CURRENT_USER="Vadim-Khristenko"' >> entrypoint.sh && \
    echo 'export CURRENT_USER' >> entrypoint.sh && \
    echo 'echo "============================================"' >> entrypoint.sh && \
    echo 'echo "Application Startup"' >> entrypoint.sh && \
    echo 'echo "Date: ${DATE_UTC} UTC"' >> entrypoint.sh && \
    echo 'echo "User: ${CURRENT_USER}"' >> entrypoint.sh && \
    echo 'echo "============================================"' >> entrypoint.sh && \
    echo 'printenv > /app/.env' >> entrypoint.sh && \
    echo 'echo "Environment Configuration:"' >> entrypoint.sh && \
    echo 'echo "- Server: ${SERVER_ADDRESS:-Not Set}"' >> entrypoint.sh && \
    echo 'echo "- PostgreSQL:"' >> entrypoint.sh && \
    echo 'echo "  Host: ${POSTGRES_HOST:-Not Set}:${POSTGRES_PORT:-Not Set}"' >> entrypoint.sh && \
    echo 'echo "  Database: ${POSTGRES_DATABASE:-Not Set}"' >> entrypoint.sh && \
    echo 'echo "  Connection: ${POSTGRES_CONN:-Not Set}"' >> entrypoint.sh && \
    echo 'echo "  JDBC URL: ${POSTGRES_JDBC_URL:-Not Set}"' >> entrypoint.sh && \
    echo 'echo "- Redis: ${REDIS_HOST:-Not Set}:${REDIS_PORT:-Not Set}"' >> entrypoint.sh && \
    echo 'echo "- Antifraud: ${ANTIFRAUD_ADDRESS:-Not Set}"' >> entrypoint.sh && \
    echo 'echo "============================================"' >> entrypoint.sh && \
    echo 'check_env_var SERVER_ADDRESS' >> entrypoint.sh && \
    echo 'check_env_var POSTGRES_HOST' >> entrypoint.sh && \
    echo 'check_env_var POSTGRES_PORT' >> entrypoint.sh && \
    echo 'check_env_var POSTGRES_DATABASE' >> entrypoint.sh && \
    echo 'check_env_var REDIS_HOST' >> entrypoint.sh && \
    echo 'check_env_var REDIS_PORT' >> entrypoint.sh && \
    echo 'check_env_var ANTIFRAUD_ADDRESS' >> entrypoint.sh && \
    echo 'SERVER_HOST=$(echo ${SERVER_ADDRESS} | cut -d: -f1)' >> entrypoint.sh && \
    echo 'SERVER_PORT=$(echo ${SERVER_ADDRESS} | cut -d: -f2)' >> entrypoint.sh && \
    echo 'export SERVER_HOST=${SERVER_HOST}' >> entrypoint.sh && \
    echo 'export SERVER_PORT=${SERVER_PORT}' >> entrypoint.sh && \
    echo 'echo "Python Server"' >> entrypoint.sh && \
    echo 'echo "Server Host: ${SERVER_HOST}"' >> entrypoint.sh && \
    echo 'echo "Server Port: ${SERVER_PORT}"' >> entrypoint.sh && \
    echo 'echo "============================================"' >> entrypoint.sh && \
    echo 'if [ ! -f ./main.py ]; then' >> entrypoint.sh && \
    echo '    echo "Ошибка: Файл main.py не найден."' >> entrypoint.sh && \
    echo '    exit 1' >> entrypoint.sh && \
    echo 'fi' >> entrypoint.sh && \
    echo 'if [ ! -x ./main.py ]; then' >> entrypoint.sh && \
    echo '    echo "Ошибка: Файл main.py не имеет прав на выполнение."' >> entrypoint.sh && \
    echo '    chmod +x ./main.py || { echo "Не удалось установить права на выполнение."; exit 1; }' >> entrypoint.sh && \
    echo 'fi' >> entrypoint.sh && \
    echo 'START_TIME=$(date +%s)' >> entrypoint.sh && \
    echo 'python ./main.py || { echo "Ошибка: Не удалось запустить main.py"; exit 1; }' >> entrypoint.sh && \
    echo 'END_TIME=$(date +%s)' >> entrypoint.sh && \
    echo 'RUN_TIME=$((END_TIME - START_TIME))' >> entrypoint.sh && \
    echo 'echo "Время выполнения: ${RUN_TIME} секунд"' >> entrypoint.sh
RUN chmod +x entrypoint.sh

COPY . .

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
#!/bin/bash

set -e
DATE_UTC="$(date -u '+%Y-%m-%d %H:%M:%S')"
export DATE_UTC
export CURRENT_USER="Vadim-Khristenko"

echo "============================================"
echo "Application Startup"
echo "Date: ${DATE_UTC} UTC"
echo "User: ${CURRENT_USER}"
echo "============================================"

printenv > /app/.env

echo "Environment Configuration:"
echo "- Server: ${SERVER_ADDRESS}"
echo "- PostgreSQL:"
echo "  Host: ${POSTGRES_HOST}:${POSTGRES_PORT}"
echo "  Database: ${POSTGRES_DATABASE}"
echo "  Connection: ${POSTGRES_CONN}"
echo "  JDBC URL: ${POSTGRES_JDBC_URL}"
echo "- Redis: ${REDIS_HOST}:${REDIS_PORT}"
echo "- Antifraud: ${ANTIFRAUD_ADDRESS}"
echo "============================================"

if [ ! -z "${SERVER_ADDRESS}" ]; then
    SERVER_HOST=$(echo ${SERVER_ADDRESS} | cut -d: -f1)
    SERVER_PORT=$(echo ${SERVER_ADDRESS} | cut -d: -f2)
    export SERVER_HOST=${SERVER_HOST}
    export SERVER_PORT=${SERVER_PORT}
fi

echo "Start Python Server"
echo "============================================"

python ./main.py
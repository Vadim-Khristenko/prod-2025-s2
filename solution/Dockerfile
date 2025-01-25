FROM python:3.12-alpine
WORKDIR /app

RUN apk add --no-cache bash

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh && ls -l /app/entrypoint.sh

COPY . .

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
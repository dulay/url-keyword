FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --upgrade pip \
 && pip install -r requirements.txt

CMD [ "python", "init_csv.py" ]

EXPOSE 8000

# 支持通过环境变量注入SECRET_KEY，默认仅用于开发

CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
ENV FLASK_RUN_HOST=0.0.0.0
CMD ["flask", "--app", "todo_project/run.py", "run"]
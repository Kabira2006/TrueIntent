# TrueIntent backend (FastAPI). Python 3.11 to match the stack.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /code

# Create a non-root user first so later layers can use it.
RUN groupadd -r appuser && useradd -r -g appuser -u 10000 appuser

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

USER appuser

EXPOSE 8000

# --reload is for local dev; production compose overrides the command.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

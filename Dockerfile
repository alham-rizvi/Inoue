FROM python:3.12-slim AS builder
WORKDIR /app
COPY pyproject.toml requirements.txt requirements-api.txt ./
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt -r requirements-api.txt

FROM python:3.12-slim AS runtime
WORKDIR /app
COPY . /app
COPY --from=builder /usr/local /usr/local
ENV PYTHONUNBUFFERED=1
CMD ["python", "inoue.py", "--help"]

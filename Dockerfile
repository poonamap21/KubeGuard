# Stage 1: Build dependencies cleanly
FROM python:3.12-alpine AS builder
WORKDIR /app
RUN apk add --no-cache ca-certificates gcc musl-dev libffi-dev
COPY requirements.txt .
RUN pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org --user --no-cache-dir -r requirements.txt

# Stage 2: Hardened runtime environment 
FROM python:3.12-alpine
WORKDIR /app

# Create a non-privileged system service user context
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Retrieve installed library wheels from the builder environment
COPY --from=builder /root/.local /home/appuser/.local
COPY ./src ./src

# Apply absolute ownership access control structures 
RUN chown -R appuser:appgroup /app
USER appuser
ENV PATH=/home/appuser/.local/bin:$PATH

EXPOSE 8080
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
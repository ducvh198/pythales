FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir pycryptodome tracetools && \
    pip install --no-cache-dir --no-deps pynblock

COPY . .
RUN pip install --no-cache-dir --no-deps .

EXPOSE 1500

CMD ["python", "examples/hsm_server.py"]

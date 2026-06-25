# ---- Builder stage: install runtime dependencies only ----
FROM python:3.13-slim AS builder

WORKDIR /build

# requirements-runtime.txt lists only the packages the scanner needs at
# runtime (boto3 + Azure SDK). requirements.txt also carries test/dev
# tooling (pytest, pytest-cov, moto, checkov) used in CI and local dev,
# which isn't needed here and is kept out of the final image.
COPY requirements-runtime.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements-runtime.txt

# ---- Final stage: slim runtime image ----
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /install /usr/local

COPY scanner/ scanner/
COPY main.py .

ENTRYPOINT ["python", "main.py"]

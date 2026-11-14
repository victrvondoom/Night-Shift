# Night Shift API + worker (one image, two commands).
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 TQDM_DISABLE=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .
USER 10001
EXPOSE 8080
CMD ["uvicorn", "beacon.server:app", "--host", "0.0.0.0", "--port", "8080"]

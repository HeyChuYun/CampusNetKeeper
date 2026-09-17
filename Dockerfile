FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY campusnet_keeper ./campusnet_keeper

RUN useradd --create-home --uid 10001 keeper \
    && mkdir -p /data \
    && chown keeper:keeper /data

USER keeper

VOLUME ["/data"]
ENTRYPOINT ["python", "-m", "campusnet_keeper"]

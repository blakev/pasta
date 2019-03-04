FROM python:3-alpine

MAINTAINER "Blake VandeMerwe <blakev@null.net>"

EXPOSE 8000

RUN mkdir -p \
    /var/log/pasta \
    /data \
    /app
WORKDIR /app

RUN apk add --update \
    build-base \
    libffi-dev \
    openssl-dev

COPY ./requirements.txt /app
RUN python -m pip install --no-cache-dir -r requirements.txt

RUN apk del --purge \
    build-base \
    libffi-dev \
    openssl-dev

COPY . /app
VOLUME /data
CMD ["gunicorn", "--config", "/app/.gunicorn", "pasta:app"]
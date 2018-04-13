FROM python:3-alpine3.6

MAINTAINER "Blake VandeMerwe <blakev@null.net>"

RUN mkdir -p \
    /var/log/pasta \
    /data \
    /app

WORKDIR /app
RUN python -m venv --system-site-packages /app/.env
RUN chmod +x /app/.env/bin/activate
RUN /app/.env/bin/activate

COPY ./requirements.txt /app
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY ./ /app

VOLUME /data
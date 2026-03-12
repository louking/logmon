ARG PYTHON_VER=3.12

# Use a stable Python 3.12 alpine image
FROM python:${PYTHON_VER}-alpine

EXPOSE 5000

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# special configuration for mysql client - https://stackoverflow.com/a/78683658
COPY client.my.cnf /home/appuser/.my.cnf

# needed for mysqlclient package to compile
# adapted from https://github.com/gliderlabs/docker-alpine/issues/181#issuecomment-444857401
#   and https://github.com/gliderlabs/docker-alpine/issues/181#issuecomment-348608168
RUN apk add --no-cache mariadb-connector-c-dev \
    && apk add --no-cache --virtual .build-deps \
        build-base \
        mariadb-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn gevent-websocket \
    && rm -rf .cache/pip \
    && apk del .build-deps

# we'll be doing mysql, mysqldump commands
RUN apk add --no-cache mysql-client

# use msmtp for sendmail, need volume with /etc/msmtprc defined
RUN apk add --no-cache msmtp && rm /usr/sbin/sendmail && ln -s /usr/bin/msmtp /usr/sbin/sendmail

# we're going to want to use bash
RUN apk add bash

# Copy the application code
COPY src .

RUN chmod +x /app/dbupgrade_and_run.sh && adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser:appuser /app
USER appuser

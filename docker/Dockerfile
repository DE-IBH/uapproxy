FROM alpine:3.15 AS build

RUN apk --no-cache add build-base python3 python3-dev postgresql-dev libffi-dev freetype-dev openjpeg-dev libimagequant-dev libwebp-dev tiff-dev libpng-dev lcms2-dev libjpeg-turbo-dev libxcb-dev zlib-dev py3-pip py3-asgiref py3-sqlparse py3-tz py3-redis py3-dateutil py3-dotenv py3-wheel py3-gunicorn

ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /usr/local/lib/python3.9/site-packages

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip3 install --no-cache-dir --prefix=/usr/local -r requirements.txt


FROM alpine:3.15

RUN apk --no-cache add python3 postgresql-libs libffi freetype openjpeg libimagequant libwebp tiff lcms2 libjpeg-turbo libxcb zlib py3-pip py3-asgiref py3-sqlparse py3-tz py3-redis py3-dateutil py3-dotenv py3-wheel py3-gunicorn

ARG USERID=8318
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /usr/local/lib/python3.9/site-packages:/usr/src/app

WORKDIR /usr/src/app

COPY --from=build /usr/local /usr/local

COPY uapproxy/manage.py \
     uapproxy/uapproxy/.env.dev \
     docker/entrypoint.sh \
     ./
COPY uapproxy/uapproxy ./uapproxy
COPY uapproxy/policer ./policer

RUN adduser -u $USERID -h /usr/src/app -D -H uapproxy && \
    ENV_FILE=.env.dev ./manage.py check --force-color && \
    ENV_FILE=.env.dev ./manage.py collectstatic --no-input --force-color && \
    mkdir -p .proxy /srv/data/db && \
    chown uapproxy:uapproxy .proxy /srv/data/db

VOLUME /usr/src/app/.proxy /srv/data/db

USER uapproxy:uapproxy
ENTRYPOINT ["/usr/src/app/entrypoint.sh"]

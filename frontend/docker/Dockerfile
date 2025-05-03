FROM nginxinc/nginx-unprivileged:alpine

ARG COMMIT_SHA=unknown
ARG APP_VERSION=0.0.0
ARG APP_DIR=/opt/app
ENV TZ=Etc/UTC \
    LANG=C.UTF-8

USER root

# Fix COPY paths relative to project root (build context)
COPY frontend/dist ${APP_DIR}
RUN chown -R 101:0 ${APP_DIR} && chmod -R g=u ${APP_DIR}

COPY frontend/docker/etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf
COPY frontend/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
USER 101
WORKDIR ${APP_DIR}
ENTRYPOINT ["/entrypoint.sh"]


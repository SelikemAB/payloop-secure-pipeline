# syntax=docker/dockerfile:1
# PayLoop runtime image. Hardening choices are explained in docs/pipeline-design.md.
# In production pin the base image by digest (php:8.3-fpm-alpine3.20@sha256:...) and let Dependabot propose updates.
FROM php:8.3-fpm-alpine3.21

RUN adduser -D -u 10001 -s /sbin/nologin app \
 && mkdir -p /srv/payloop/var \
 && chown app:app /srv/payloop/var

WORKDIR /srv/payloop
# Application code is root-owned and read-only to the runtime user; only var/ is writable.
COPY --chown=root:root app/ /srv/payloop/
COPY docker/php-fpm.conf /usr/local/etc/php-fpm.d/zz-payloop.conf
COPY docker/php.ini /usr/local/etc/php/conf.d/zz-payloop.ini
RUN chown -R app:app /srv/payloop/var && chmod -R go-w /srv/payloop

USER 10001
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD pidof php-fpm >/dev/null || exit 1
CMD ["php-fpm", "--nodaemonize"]

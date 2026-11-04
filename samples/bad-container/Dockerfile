# Intentionally insecure: used only to prove the pipeline gate fails. Do not copy.
FROM php:latest
ADD https://example.com/install.sh /install.sh
RUN chmod +x /install.sh && /install.sh
COPY . /var/www/html
EXPOSE 22 80
CMD ["php", "-S", "0.0.0.0:80", "-t", "/var/www/html"]

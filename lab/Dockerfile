# CVE-2026-109618/109619 — LOCAL vulnerable lab target (nginx + php-fpm).
# php:8.2.34 predates the 2026-10-21 fixes (8.2.35+). Pre-fix alternatives:
#   php:8.3.35-fpm, php:8.4.26-fpm, php:8.5.11-fpm
FROM php:8.2.34-fpm

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx \
    && rm -rf /var/lib/apt/lists/*

COPY nginx-site.conf /etc/nginx/sites-available/default
COPY webroot/ /var/www/html/

# Vulnerable-by-default session configuration (all values are PHP defaults
# except cleanup=0, which widens the race window; see VERIFICATION.md).
RUN { \
      echo 'session.upload_progress.enabled=1'; \
      echo 'session.upload_progress.cleanup=0'; \
      echo 'session.use_strict_mode=0'; \
      echo 'session.save_handler=files'; \
      echo 'session.save_path=/var/lib/php/sessions'; \
      echo 'display_errors=1'; \
      echo 'error_reporting=E_ALL'; \
    } > /usr/local/etc/php/conf.d/99-vuln.ini \
    && mkdir -p /var/lib/php/sessions \
    && chown -R www-data:www-data /var/lib/php/sessions /var/www/html

EXPOSE 80
CMD ["sh", "-c", "php-fpm -D && nginx -g 'daemon off;'"]

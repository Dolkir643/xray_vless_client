# Базовый образ с bashio (s6, логирование)
ARG BUILD_FROM=ghcr.io/hassio-addons/base:14.0.0
FROM ${BUILD_FROM}

# Бинарник Xray из официального образа
COPY --from=ghcr.io/xtls/xray-core:latest /usr/local/bin/xray /usr/local/bin/xray

# Python3 для генератора конфига из VLESS-ссылки
RUN apk add --no-cache python3

RUN chmod +x /usr/local/bin/xray

COPY gen_config.py /usr/share/xray/gen_config.py
COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]

#!/usr/bin/with-contenv bashio

VLESS_URL=$(bashio::config 'vless_url')
SOCKS_PORT=$(bashio::config 'socks_port')
CONFIG_PATH="/tmp/xray_config.json"
export VLESS_URL
export SOCKS_PORT

bashio::log.info "Генерация конфига Xray из VLESS-ссылки..."
if ! python3 /usr/share/xray/gen_config.py > "$CONFIG_PATH"; then
  bashio::log.fatal "Ошибка разбора VLESS-ссылки. Проверьте формат (vless://uuid@host:port?params)."
  exit 1
fi

bashio::log.info "SOCKS5-прокси будет доступен на порту ${SOCKS_PORT}. Запуск Xray..."
exec xray run -c "$CONFIG_PATH"

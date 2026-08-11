#!/usr/bin/env bash
# Установка onionwatch на Ubuntu 24.04. Запускать от root из каталога,
# где лежат onionwatch.py, dashboard.html, onionwatch.service, config.example.json.
#
#   sudo ./install.sh                 # tor из репозитория Tor Project
#   sudo ./install.sh --universe      # tor из штатного репозитория Ubuntu
#
# Скрипт идемпотентный: повторный запуск обновляет код и не трогает config.json.

set -euo pipefail

APP_DIR=/opt/onionwatch
CFG_DIR=/etc/onionwatch
USER_NAME=onionwatch
TOR_SOURCE=torproject
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '\n\033[1;35m==>\033[0m %s\n' "$1"; }
die() { printf '\033[1;31mОшибка:\033[0m %s\n' "$1" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "нужны права root: sudo ./install.sh"
if [[ ${1:-} == "--universe" ]]; then TOR_SOURCE=universe; fi

for f in onionwatch.py dashboard.html onionwatch.service config.example.json; do
  [[ -f "${SRC_DIR}/${f}" ]] || die "рядом со скриптом нет файла ${f}"
done

if ! grep -q 'VERSION_ID="24.04"' /etc/os-release 2>/dev/null; then
  printf 'Внимание: система не Ubuntu 24.04, продолжаю на свой страх и риск.\n' >&2
fi

say "Обновляю списки пакетов"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gpg sqlite3

if [[ ${TOR_SOURCE} == torproject ]]; then
  say "Подключаю репозиторий Tor Project"
  apt-get install -y -qq apt-transport-https
  curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc \
    | gpg --dearmor --yes -o /usr/share/keyrings/deb.torproject.org-keyring.gpg
  codename="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-noble}")"
  cat > /etc/apt/sources.list.d/tor.sources <<EOF
Types: deb deb-src
URIs: https://deb.torproject.org/torproject.org/
Suites: ${codename}
Components: main
Signed-By: /usr/share/keyrings/deb.torproject.org-keyring.gpg
EOF
  if apt-get update -qq 2>/dev/null; then
    apt-get install -y -qq tor deb.torproject.org-keyring
  else
    printf 'Репозиторий Tor Project недоступен для %s, ставлю пакет Ubuntu.\n' "${codename}" >&2
    rm -f /etc/apt/sources.list.d/tor.sources
    apt-get update -qq && apt-get install -y -qq tor
  fi
else
  say "Ставлю tor из репозитория Ubuntu"
  apt-get install -y -qq tor
fi

systemctl enable --now tor.service >/dev/null 2>&1 || true
systemctl enable --now tor@default.service >/dev/null 2>&1 || true

say "Создаю пользователя и каталоги"
if ! id -u "${USER_NAME}" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir "${APP_DIR}" \
          --shell /usr/sbin/nologin "${USER_NAME}"
fi
install -d -o root -g root -m 0755 "${APP_DIR}"
install -d -o root -g "${USER_NAME}" -m 0750 "${CFG_DIR}"

say "Копирую файлы приложения"
install -o root -g root -m 0644 "${SRC_DIR}/onionwatch.py"  "${APP_DIR}/onionwatch.py"
install -o root -g root -m 0644 "${SRC_DIR}/dashboard.html" "${APP_DIR}/dashboard.html"
if [[ -f "${SRC_DIR}/README.md" ]]; then
  install -m 0644 "${SRC_DIR}/README.md" "${APP_DIR}/README.md"
fi

if [[ ! -f "${CFG_DIR}/config.json" ]]; then
  sed -e 's#"db_path": "onionwatch.db"#"db_path": "/var/lib/onionwatch/onionwatch.db"#' \
      "${SRC_DIR}/config.example.json" > "${CFG_DIR}/config.json"
  chown root:"${USER_NAME}" "${CFG_DIR}/config.json"
  chmod 0640 "${CFG_DIR}/config.json"
  NEW_CONFIG=1
else
  NEW_CONFIG=0
  say "Конфиг ${CFG_DIR}/config.json уже есть — не трогаю"
fi

say "Ставлю systemd-юнит"
install -m 0644 "${SRC_DIR}/onionwatch.service" /etc/systemd/system/onionwatch.service
systemctl daemon-reload
systemctl enable onionwatch.service >/dev/null

if [[ ${NEW_CONFIG} -eq 1 ]]; then
  cat <<EOF

Установка завершена, но сервис ещё не запущен: в конфиге стоят адреса-заглушки.

  1. sudo nano ${CFG_DIR}/config.json      # впишите свои .onion-адреса
  2. sudo systemctl start onionwatch
  3. sudo systemctl status onionwatch
  4. с ноутбука: ssh -N -L 8088:127.0.0.1:8088 $(logname 2>/dev/null || echo user)@<IP-сервера>
     и откройте http://127.0.0.1:8088/
EOF
else
  systemctl restart onionwatch
  say "Сервис перезапущен: systemctl status onionwatch"
fi

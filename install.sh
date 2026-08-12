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
STATE_DIR=/var/lib/onionwatch
USER_NAME=onionwatch
TOR_SOURCE=torproject
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '\n\033[1;35m==>\033[0m %s\n' "$1"; }
die() { printf '\033[1;31mОшибка:\033[0m %s\n' "$1" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "нужны права root: sudo ./install.sh"
if [[ ${1:-} == "--universe" ]]; then TOR_SOURCE=universe; fi

for f in onionwatch.py dashboard.html admin.html onionwatch.service config.example.json; do
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
install -o root -g root -m 0644 "${SRC_DIR}/admin.html"     "${APP_DIR}/admin.html"
if [[ -f "${SRC_DIR}/README.md" ]]; then
  install -m 0644 "${SRC_DIR}/README.md" "${APP_DIR}/README.md"
fi

if [[ ! -f "${CFG_DIR}/config.json" ]]; then
  sed -e "s#\"db_path\": \"onionwatch.db\"#\"db_path\": \"${STATE_DIR}/onionwatch.db\"#" \
      "${SRC_DIR}/config.example.json" > "${CFG_DIR}/config.json"
  chown root:"${USER_NAME}" "${CFG_DIR}/config.json"
  chmod 0640 "${CFG_DIR}/config.json"
else
  say "Конфиг ${CFG_DIR}/config.json уже есть — не трогаю"
fi

say "Ставлю systemd-юнит"
install -m 0644 "${SRC_DIR}/onionwatch.service" /etc/systemd/system/onionwatch.service
systemctl daemon-reload
systemctl enable onionwatch.service >/dev/null

# Каталог базы обычно создаёт systemd (StateDirectory), но администратора
# нужно завести до первого старта — создаём каталог сами.
install -d -o "${USER_NAME}" -g "${USER_NAME}" -m 0750 "${STATE_DIR}"

DB="${STATE_DIR}/onionwatch.db"

# База и её WAL-файлы должны принадлежать сервису. Если что-то запускалось от
# root, они остаются root:root, и демон падает с «readonly database».
shopt -s nullglob
for f in "${DB}" "${DB}"-*; do
  chown "${USER_NAME}:${USER_NAME}" "$f"
done
shopt -u nullglob

# Целей в конфиге больше нет: они заводятся в админке, а вход в неё — по
# логину и паролю. Без администратора добавить их будет некому.
#
# Администратора заводим до старта сервиса и строго от имени ${USER_NAME}:
# запуск от root создал бы базу с чужим владельцем. По той же причине sqlite3
# зовём только на уже существующем файле — на отсутствующем он молча создаёт
# пустую базу от того, кто его запустил.
ADMINS=0
if [[ -s ${DB} ]]; then
  ADMINS=$(sudo -u "${USER_NAME}" sqlite3 -readonly "${DB}" \
           "SELECT COUNT(*) FROM admins" 2>/dev/null || echo 0)
fi
if [[ ${ADMINS} -eq 0 ]]; then
  if [[ -t 0 ]]; then
    say "Создаю администратора для входа в админку"
    sudo -u "${USER_NAME}" /usr/bin/python3 "${APP_DIR}/onionwatch.py" \
         --config "${CFG_DIR}/config.json" --set-admin admin || \
      printf 'Администратор не создан, повторите команду вручную.\n' >&2
  else
    printf '\nАдминистратор не создан (запуск без терминала). Выполните:\n  sudo -u %s python3 %s/onionwatch.py --config %s/config.json --set-admin admin\n' \
           "${USER_NAME}" "${APP_DIR}" "${CFG_DIR}" >&2
  fi
fi

systemctl restart onionwatch
say "Сервис запущен: systemctl status onionwatch"

cat <<EOF

Готово. Дальше:

  1. с ноутбука: ssh -N -L 8088:127.0.0.1:8088 $(logname 2>/dev/null || echo user)@<IP-сервера>
  2. откройте http://127.0.0.1:8088/admin и войдите под созданным логином
  3. добавьте onion-адреса — они сразу попадут на дашборд http://127.0.0.1:8088/

Конфиг ${CFG_DIR}/config.json задаёт только порты, интервалы и таймауты.
EOF

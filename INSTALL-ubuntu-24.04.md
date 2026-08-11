# Установка onionwatch на VPS с Ubuntu 24.04

Полное руководство: от чистого сервера до работающего мониторинга с доступом к
дашборду, автозапуском, оповещениями и резервными копиями.

**Что понадобится:** VPS с Ubuntu 24.04 LTS (хватит 1 vCPU / 512 МБ RAM / 5 ГБ
диска), доступ по SSH с правами sudo, файлы `onionwatch.py`, `dashboard.html`,
`config.example.json`, `onionwatch.service`, `install.sh`.

**Время:** 15–20 минут.

Итоговая раскладка по файловой системе:

| Путь | Что там |
|---|---|
| `/opt/onionwatch/` | код: `onionwatch.py`, `dashboard.html` (только чтение) |
| `/etc/onionwatch/config.json` | конфиг с целями, `0640 root:onionwatch` |
| `/var/lib/onionwatch/onionwatch.db` | история проверок (SQLite) |
| `/etc/systemd/system/onionwatch.service` | юнит автозапуска |
| `/etc/tor/torrc` | настройки Tor |

---

## 1. Подготовка сервера

Подключитесь к серверу и обновите систему:

```bash
ssh root@<IP-сервера>
apt update && apt upgrade -y
```

### 1.1. Отдельный пользователь вместо root

Если вы зашли под root, заведите обычного пользователя — дальше всё делается
через `sudo`:

```bash
adduser admin
usermod -aG sudo admin
rsync --archive --chown=admin:admin ~/.ssh /home/admin   # перенести ключи SSH
```

Переподключитесь как `admin` и убедитесь, что `sudo` работает, прежде чем
закрывать root-сессию. Затем отключите вход по паролю и под root:

```bash
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/; s/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

В Ubuntu 24.04 SSH запускается через сокет-активацию (`ssh.socket`), поэтому
перезапускать нужно именно `ssh`, а не `sshd`.

### 1.2. Файрвол

Наружу не должно смотреть ничего, кроме SSH: дашборд слушает только петлевой
интерфейс, а Tor работает исходящими соединениями.

```bash
sudo ufw allow OpenSSH
sudo ufw --force enable
sudo ufw status verbose        # Default: deny (incoming), allow (outgoing)
```

### 1.3. Время

Tor не построит цепочку при съехавших часах — это самая частая причина
загадочных сбоев. Проверьте, что синхронизация включена:

```bash
timedatectl
# System clock synchronized: yes
# NTP service: active
```

Если `NTP service: inactive` — `sudo timedatectl set-ntp true`.

### 1.4. Автоматические обновления безопасности

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades   # ответить «Да»
```

---

## 2. Установка Tor

Tor Project рекомендует ставить `tor` из своего репозитория, а не из universe
Ubuntu: <cite index="7-1">пакеты в universe обновляются нерегулярно, из-за чего можно остаться без исправлений стабильности и безопасности</cite>.

```bash
sudo apt install -y apt-transport-https ca-certificates curl gpg

curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/deb.torproject.org-keyring.gpg

sudo tee /etc/apt/sources.list.d/tor.sources >/dev/null <<'EOF'
Types: deb deb-src
URIs: https://deb.torproject.org/torproject.org/
Suites: noble
Components: main
Signed-By: /usr/share/keyrings/deb.torproject.org-keyring.gpg
EOF

sudo apt update
sudo apt install -y tor deb.torproject.org-keyring
```

Пакет `deb.torproject.org-keyring` сам обновляет ключ подписи, когда придёт срок.

> Если `apt update` ругается, что для `noble` нет Release-файла, репозиторий для
> этого выпуска временно недоступен — поставьте штатный пакет
> (`sudo rm /etc/apt/sources.list.d/tor.sources && sudo apt update && sudo apt install -y tor`)
> и вернитесь к репозиторию Tor Project позже.

### 2.1. Проверка

На Debian и Ubuntu настоящий процесс — это экземпляр `tor@default`, а
`tor.service` только запускает его.

```bash
sudo systemctl enable --now tor.service tor@default.service
systemctl status tor@default --no-pager
journalctl -u tor@default -n 20 --no-pager | grep -i bootstrapped
# Bootstrapped 100% (done): Done
```

Убедитесь, что SOCKS-порт поднят и трафик реально идёт через Tor:

```bash
ss -ltnp | grep 9050
# LISTEN 0 4096 127.0.0.1:9050

curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"..."}
```

Штатный конфиг менять не нужно: `SocksPort 9050` на `127.0.0.1` и изоляция
цепочек по SOCKS-авторизации включены по умолчанию. Если хочется задать явно,
допишите в `/etc/tor/torrc`:

```
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth
```

и выполните `sudo systemctl reload tor@default`.

---

## 3. Установка onionwatch

Python в Ubuntu 24.04 — 3.12, этого достаточно; ставить ничего не нужно.

### Вариант А: скриптом

Скопируйте файлы на сервер с локальной машины:

```bash
scp onionwatch.py dashboard.html config.example.json onionwatch.service \
    install.sh README.md admin@<IP-сервера>:~/onionwatch/
```

и запустите:

```bash
cd ~/onionwatch && chmod +x install.sh && sudo ./install.sh
```

Скрипт делает всё из шагов 2–4: подключает репозиторий Tor, ставит `tor`,
создаёт системного пользователя `onionwatch`, раскладывает файлы, ставит юнит и
включает автозапуск. Он идемпотентный — повторный запуск обновит код и не
перезапишет ваш `config.json`. Если Tor уже установлен, используйте
`sudo ./install.sh --universe`, чтобы не трогать источники пакетов.

Дальше переходите к шагу 4 (конфигурация).

### Вариант Б: вручную

```bash
# системный пользователь без входа в систему
sudo useradd --system --no-create-home --home-dir /opt/onionwatch \
             --shell /usr/sbin/nologin onionwatch

# каталоги
sudo install -d -o root -g root -m 0755 /opt/onionwatch
sudo install -d -o root -g onionwatch -m 0750 /etc/onionwatch

# код: владелец root, сервису доступен только на чтение
sudo install -o root -g root -m 0644 onionwatch.py  /opt/onionwatch/
sudo install -o root -g root -m 0644 dashboard.html /opt/onionwatch/

# конфиг
sudo install -o root -g onionwatch -m 0640 config.example.json /etc/onionwatch/config.json

# юнит
sudo install -m 0644 onionwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable onionwatch
```

Каталог для базы создавать не нужно: `StateDirectory=onionwatch` в юните
заставит systemd создать `/var/lib/onionwatch` с правильными правами при первом
запуске.

### Что делает юнит

Помимо автозапуска и перезапуска при падении, юнит серьёзно ограничивает
процесс. Главная строка:

```
IPAddressDeny=any
IPAddressAllow=localhost
```

Сервису разрешён только петлевой интерфейс. Даже если в коде появится ошибка или
цель окажется не onion-адресом, прямого соединения в интернет мимо Tor не
произойдёт — ядро его не пропустит. Остальное — стандартный набор: запрет
повышения привилегий, файловая система только на чтение, пустой набор
capabilities, фильтр системных вызовов.

Проверить, что systemd принял все ограничения:

```bash
systemd-analyze security onionwatch.service | tail -5
```

---

## 4. Конфигурация

```bash
sudo nano /etc/onionwatch/config.json
```

Минимально нужно поменять две вещи — путь к базе и адреса целей:

```json
{
  "tor_socks": "127.0.0.1:9050",
  "listen": "127.0.0.1:8088",
  "db_path": "/var/lib/onionwatch/onionwatch.db",

  "check_interval": 300,
  "timeout": 60,
  "concurrency": 6,
  "retention_days": 30,
  "isolate_circuits": true,

  "targets": [
    {
      "name": "my-blog",
      "url": "http://ваш-адрес.onion/",
      "expect_status": [200],
      "expect_text": "<title>",
      "note": "основной сайт"
    }
  ]
}
```

`db_path` обязательно должен указывать на `/var/lib/onionwatch/` — в остальные
каталоги сервису писать запрещено. Описание всех полей — в `README.md`.

Адреса берите из официального источника сервиса и вставляйте копированием:
ошибка в одном символе onion-адреса даёт совершенно другой сервис.

Проверьте конфиг разовым прогоном ещё до запуска демона:

```bash
sudo -u onionwatch python3 /opt/onionwatch/onionwatch.py \
     --config /etc/onionwatch/config.json --once
```

Команда напечатает таблицу и вернёт код `1`, если что-то недоступно. Ошибка
`descriptor_not_found` означает, что сервис выключен или адрес неверен; ошибки
`tor_down` быть не должно.

---

## 5. Запуск

```bash
sudo systemctl start onionwatch
systemctl status onionwatch --no-pager
journalctl -u onionwatch -f          # живой лог проверок, Ctrl+C для выхода
```

В логе должны появиться строки вида `[12:30:05] UP my-blog 2140 ms 200`.
Локальная проверка API:

```bash
curl -s http://127.0.0.1:8088/api/state | python3 -m json.tool | head -20
```

---

## 6. Доступ к дашборду

Дашборд слушает `127.0.0.1:8088` и не имеет собственной аутентификации, поэтому
открывать порт наружу нельзя. Выберите один из трёх способов.

### Вариант А: SSH-туннель (рекомендуется)

Ничего настраивать на сервере не нужно. С локальной машины:

```bash
ssh -N -L 8088:127.0.0.1:8088 admin@<IP-сервера>
```

Пока команда работает, дашборд открывается на `http://127.0.0.1:8088/` в
обычном браузере. Это самый безопасный вариант: наружу по-прежнему торчит только
SSH.

### Вариант Б: дашборд как onion-сервис с клиентской авторизацией

Удобно, если хочется заходить с телефона и без SSH. Доступ получат только те, у
кого есть приватный ключ.

**1. Сгенерируйте пару ключей x25519** (на своей машине или на сервере):

```bash
openssl genpkey -algorithm x25519 -out /tmp/ow.pem
openssl pkey -in /tmp/ow.pem -pubout -out /tmp/ow.pub.pem
python3 - <<'EOF'
import base64
def key(path):
    der = base64.b64decode("".join(l for l in open(path) if "-----" not in l))
    return base64.b32encode(der[-32:]).decode().rstrip("=")
print("PRIV:", key("/tmp/ow.pem"))
print("PUB :", key("/tmp/ow.pub.pem"))
EOF
```

Приватный ключ сохраните в менеджере паролей, файлы из `/tmp` удалите.

**2. Опишите сервис** в `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/onionwatch/
HiddenServicePort 80 127.0.0.1:8088
```

**3. Положите публичный ключ** в список разрешённых клиентов:

```bash
sudo install -d -o debian-tor -g debian-tor -m 0700 /var/lib/tor/onionwatch/authorized_clients
echo "descriptor:x25519:<ВСТАВЬТЕ_PUB>" | \
  sudo tee /var/lib/tor/onionwatch/authorized_clients/laptop.auth >/dev/null
sudo chown -R debian-tor:debian-tor /var/lib/tor/onionwatch
sudo chmod 600 /var/lib/tor/onionwatch/authorized_clients/laptop.auth
```

**4. Перезапустите Tor и заберите адрес:**

```bash
sudo systemctl restart tor@default
sudo cat /var/lib/tor/onionwatch/hostname
```

Откройте этот адрес в Tor Browser — он спросит приватный ключ, вставьте
значение `PRIV`. Каждому устройству лучше выдать отдельный `.auth`-файл, чтобы
можно было отозвать доступ по одному (удалить файл и перезапустить tor).

### Вариант В: nginx с паролем и TLS

Годится, только если у вас есть домен и вы понимаете, что дашборд станет виден
всему интернету:

```bash
sudo apt install -y nginx apache2-utils certbot python3-certbot-nginx
sudo htpasswd -c /etc/nginx/.onionwatch admin
```

`/etc/nginx/sites-available/onionwatch`:

```nginx
server {
    listen 80;
    server_name status.example.com;
    location / {
        auth_basic "onionwatch";
        auth_basic_user_file /etc/nginx/.onionwatch;
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/onionwatch /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo ufw allow 'Nginx Full'
sudo certbot --nginx -d status.example.com
```

Учтите: так вы публично раскрываете список onion-адресов, которые мониторите.

---

## 7. Оповещения о падениях

Дашборд удобно смотреть глазами, но о сбое лучше узнавать сразу. Скрипт ниже
сравнивает текущее состояние с прошлым и шлёт сообщение только при изменениях —
когда цель упала и когда вернулась.

```bash
sudo tee /usr/local/bin/onionwatch-alert >/dev/null <<'PY'
#!/usr/bin/env python3
import json, os, socket, urllib.request

API = os.environ.get("OW_API", "http://127.0.0.1:8088/api/state")
HOOK = os.environ.get("OW_WEBHOOK", "")
STATE = "/var/lib/onionwatch/alert-state.json"

def notify(text):
    print(text, flush=True)
    if HOOK:
        req = urllib.request.Request(HOOK, data=json.dumps({"text": text}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15).read()

state = json.load(urllib.request.urlopen(API, timeout=15))
down = {t["name"]: (t["last"] or {}).get("error", "нет данных")
        for t in state["targets"] if not (t["last"] or {}).get("ok")}
try:
    prev = set(json.load(open(STATE)))
except Exception:
    prev = set()

host = socket.gethostname()
if new := set(down) - prev:
    notify(f"[{host}] недоступны: " + "; ".join(f"{n} — {down[n]}" for n in sorted(new)))
if back := prev - set(down):
    notify(f"[{host}] снова доступны: " + ", ".join(sorted(back)))

with open(STATE, "w") as fh:
    json.dump(sorted(down), fh)
PY
sudo chmod 755 /usr/local/bin/onionwatch-alert
```

Таймер, запускающий его раз в 5 минут:

```bash
sudo tee /etc/systemd/system/onionwatch-alert.service >/dev/null <<'EOF'
[Unit]
Description=Проверка состояния onionwatch и отправка оповещений
After=onionwatch.service

[Service]
Type=oneshot
User=onionwatch
Environment=OW_WEBHOOK=https://пример/вебхук
ExecStart=/usr/local/bin/onionwatch-alert
StateDirectory=onionwatch
EOF

sudo tee /etc/systemd/system/onionwatch-alert.timer >/dev/null <<'EOF'
[Unit]
Description=Оповещения onionwatch каждые 5 минут

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now onionwatch-alert.timer
sudo systemctl start onionwatch-alert.service   # проверить сразу
journalctl -u onionwatch-alert -n 20 --no-pager
```

Без `OW_WEBHOOK` скрипт просто пишет в журнал — это уже даёт историю падений.
Подойдёт любой вебхук, принимающий JSON с полем `text`; для Telegram проще
сделать `notify()` через Bot API.

Одна тонкость: не поднимайте частоту оповещений выше интервала проверок —
чаще, чем `check_interval`, состояние всё равно не меняется.

---

## 8. Эксплуатация

**Логи и статус**

```bash
systemctl status onionwatch
journalctl -u onionwatch -f              # хвост живьём
journalctl -u onionwatch --since "1 hour ago" | grep DOWN
journalctl -u tor@default --since today  # проблемы самой сети Tor
```

**Изменение целей**

```bash
sudo nano /etc/onionwatch/config.json
sudo systemctl restart onionwatch        # конфиг читается при старте
```

История уже удалённых целей остаётся в базе и просто перестаёт показываться.

**Обновление кода**

```bash
scp onionwatch.py dashboard.html admin@<IP>:~/onionwatch/
sudo install -o root -g root -m 0644 ~/onionwatch/onionwatch.py  /opt/onionwatch/
sudo install -o root -g root -m 0644 ~/onionwatch/dashboard.html /opt/onionwatch/
sudo systemctl restart onionwatch
```

**Резервная копия базы**

Копировать файл на ходу нельзя — база в режиме WAL. Правильный способ:

```bash
sudo -u onionwatch sqlite3 /var/lib/onionwatch/onionwatch.db \
     ".backup '/var/lib/onionwatch/backup.db'"
```

**Сколько занимает места.** Одна проверка — примерно 100 байт. Десять целей с
интервалом 5 минут за 30 дней дают около 9 МБ. Хранение регулируется полем
`retention_days`, чистка идёт раз в час автоматически.

**Ресурсы.** Процесс потребляет десятки мегабайт RAM; основной расход даёт сам
`tor`. На 512 МБ спокойно живут обе службы и пара десятков целей.

**Удаление**

```bash
sudo systemctl disable --now onionwatch onionwatch-alert.timer
sudo rm -f /etc/systemd/system/onionwatch*.{service,timer}
sudo rm -rf /opt/onionwatch /etc/onionwatch /var/lib/onionwatch
sudo userdel onionwatch
sudo systemctl daemon-reload
```

---

## 9. Если что-то не работает

| Симптом | Причина и что делать |
|---|---|
| В логе у всех целей `tor_down` | `tor` не запущен: `systemctl status tor@default`, `ss -ltnp \| grep 9050` |
| Все цели `descriptor_not_found` | Tor не догрузился: ищите `Bootstrapped 100%` в `journalctl -u tor@default`. Часто виноваты часы — проверьте `timedatectl` |
| Одна цель `descriptor_not_found` | сервис выключен либо адрес с опечаткой |
| `client_auth_missing` | сервис требует клиентский ключ; onionwatch авторизацию не передаёт — добавьте ключ в `ClientOnionAuthDir` в `torrc` |
| `timeout` у всех целей | увеличьте `timeout` до 90–120 с и снизьте `concurrency`; на слабых VPS цепочки строятся долго |
| Сервис падает с `Read-only file system` | `db_path` вне `/var/lib/onionwatch` — юнит запрещает запись в другие места |
| `Permission denied` при старте | конфиг недоступен пользователю: `sudo chown root:onionwatch /etc/onionwatch/config.json && sudo chmod 640 …` |
| Дашборд пустой, баннер об ошибке API | процесс не запущен либо туннель ведёт не на тот порт: `curl -s 127.0.0.1:8088/api/state` на самом сервере |
| `apt update` не видит репозиторий Tor | нет сборки под `noble` — временно поставьте пакет из universe |
| Первые минуты все цели красные | это нормально: первая проверка каждой цели стартует со случайной задержкой, а цепочка строится 5–30 секунд |

---

## 10. Итоговый чеклист

- [ ] Вход по SSH-ключу, root-логин и пароли отключены
- [ ] `ufw` включён, наружу открыт только SSH
- [ ] `timedatectl` показывает синхронизацию времени
- [ ] `tor@default` активен, `curl --socks5-hostname` возвращает `"IsTor":true`
- [ ] `onionwatch` в статусе `active (running)` и включён в автозапуск
- [ ] `--once` отрабатывает без ошибок `tor_down`
- [ ] Дашборд открывается через SSH-туннель или onion-адрес с клиентским ключом
- [ ] Таймер оповещений включён и хотя бы раз отработал
- [ ] Настроено резервное копирование базы, если история важна

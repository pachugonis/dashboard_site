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
| `/opt/onionwatch/` | код: `onionwatch.py`, `dashboard.html`, `admin.html` (только чтение) |
| `/etc/onionwatch/config.json` | конфиг: порты и таймауты, `0640 root:onionwatch` |
| `/var/lib/onionwatch/onionwatch.db` | цели, история проверок, администраторы (SQLite) |
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

Одну строку в `/etc/tor/torrc` дописать всё же стоит:

```
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth ExtendedErrors
```

и выполнить `sudo systemctl reload tor@default`.

`SocksPort 9050` на `127.0.0.1` и изоляция цепочек включены и по умолчанию, а вот
`ExtendedErrors` — нет, и без него Tor не сообщает причину отказа: все сбои
приходят одним кодом и попадают в лог как `general_failure`. С этим флагом
onionwatch отличает выключенный сервис (`descriptor_not_found`) от недостроенной
цепочки (`rendezvous_failed`) и от запроса клиентского ключа
(`client_auth_missing`).

Необязательно, но полезно, если проверки часто срываются: onionwatch держится за
одну цепочку на цель, чтобы не строить её заново каждые пять минут, однако Tor
всё равно выдаёт новую после `MaxCircuitDirtiness` — по умолчанию 600 секунд.
Строкой `MaxCircuitDirtiness 1800` в том же `torrc` цепочка живёт дольше и
переиспользуется всеми проверками подряд, а не каждой второй. Обратная сторона —
дольше один и тот же путь через сеть; для мониторинга это приемлемо, для анонимной
работы в браузере — нет, поэтому отдельный `SocksPort` для onionwatch тут уместен.

---

## 3. Установка onionwatch

Python в Ubuntu 24.04 — 3.12, этого достаточно; ставить ничего не нужно.

### Вариант А: скриптом

Скопируйте файлы на сервер с локальной машины:

```bash
scp onionwatch.py dashboard.html admin.html config.example.json onionwatch.service \
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

Адресов сервисов в конфиге нет — они заводятся в админке и хранятся в базе.
Здесь задаются только порты, интервалы и таймауты:

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

  "attempts": 3,
  "retry_delay": 20,
  "circuit_ttl": 1800,

  "require_login": false,
  "session_hours": 12
}
```

`db_path` обязательно должен указывать на `/var/lib/onionwatch/` — в остальные
каталоги сервису писать запрещено. Описание всех полей — в `README.md`.

Поставьте `"require_login": true`, если дашборд будет виден кому-то кроме вас:
тогда логин спросят не только в админке, но и на главной странице.

### Администратор

Без администратора в админку не войти, а значит и цели добавить некому.
`install.sh` предлагает создать его сам; вручную это делается так:

```bash
sudo -u onionwatch python3 /opt/onionwatch/onionwatch.py \
     --config /etc/onionwatch/config.json --set-admin admin
```

Пароль спрашивается дважды и не остаётся ни в логах, ни в истории команд.
Той же командой меняется забытый пароль. Минимальная длина — 10 символов;
хранится scrypt-хэш со случайной солью.

### Цели

Откройте `/admin` (как достучаться до порта — раздел 6), войдите и добавьте
адреса. Первая проверка новой цели ставится в очередь сразу, перезапускать
демон не нужно.

К цели можно приложить изображение — оно появится на её карточке. PNG, JPEG и
WebP обрезаются в квадрат прямо в браузере; GIF сохраняется как есть, чтобы не
потерять анимацию, и обрезается уже при показе. Предел — 512 КБ на файл. Всё
лежит в базе, поэтому резервная копия забирает картинки вместе с историей.

Адреса берите из официального источника сервиса и вставляйте копированием:
ошибка в одном символе onion-адреса даёт совершенно другой сервис. Форма
проверяет длину и алфавит v3-адреса, но подменённый на другой корректный адрес
она отличить не может.

Проверить всё разом можно разовым прогоном:

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

Дашборд слушает `127.0.0.1:8088`. Паролем закрыта только админка `/admin`;
главная страница по умолчанию открыта всем, кто до неё дотянулся. Прямо в
интернет порт выставлять всё равно не стоит — пароль от админки уйдёт по
открытому HTTP. Выберите один из четырёх способов.

Если дашборд должен быть доступен только вам, поставьте `"require_login": true`
в конфиге: тогда логин спросят и на главной. Для публичного дашборда оставьте
значение по умолчанию `false`.

### Вариант А: SSH-туннель (рекомендуется)

Ничего настраивать на сервере не нужно. С локальной машины:

```bash
ssh -N -L 8088:127.0.0.1:8088 admin@<IP-сервера>
```

Пока команда работает, дашборд открывается на `http://127.0.0.1:8088/` в
обычном браузере. Это самый безопасный вариант: наружу по-прежнему торчит только
SSH.

### Вариант Б: дашборд как onion-сервис, открытый всем

Самый короткий путь, если дашборд задуман публичным: адрес знает кто угодно,
паролем закрыта только админка.

**1. Опишите сервис** в `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/onionwatch/
HiddenServicePort 80 127.0.0.1:8088
```

**2. Перезапустите Tor и заберите адрес:**

```bash
sudo systemctl restart tor@default
sudo cat /var/lib/tor/onionwatch/hostname
```

Каталоги и ключи Tor создаст сам. Через минуту-две после старта дескриптор
публикуется, и адрес открывается в Tor Browser — обычный браузер зону `.onion`
не резолвит.

> Пустой каталог `authorized_clients` внутри `HiddenServiceDir` — это норма:
> Tor создаёт его сам при каждом запуске, и удалять его не нужно (он всё равно
> вернётся). Клиентская авторизация включается только тогда, когда внутри
> появляется хотя бы один `.auth`-файл — см. вариант В.

### Вариант В: onion-сервис с клиентской авторизацией

То же самое, но доступ получат только те, у кого есть приватный ключ. Имеет
смысл, если дашборд не должен быть виден посторонним даже при утечке адреса.

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

**5. Убедитесь, что ключ на месте и в правильном формате:**

```bash
sudo ls -l /var/lib/tor/onionwatch/authorized_clients/
sudo cat /var/lib/tor/onionwatch/authorized_clients/laptop.auth
```

Нужен хотя бы один файл с суффиксом `.auth` и одной строкой
`descriptor:x25519:<52 символа base32 в верхнем регистре>`. Частые ошибки —
другой суффикс (Tor читает только `.auth`), переносы строк, приватный ключ
вместо публичного и нижний регистр.

Если каталог пуст, клиентская авторизация просто выключена и сервис открыт
всем — это его штатное состояние, а не поломка.

### Вариант Г: nginx с паролем и TLS

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
когда цель упала, когда сменила состояние и когда вернулась в норму. Состояний
три, и в тексте они разведены: «не отвечает» и «отвечает не тем» требуют разной
реакции (см. раздел «Три состояния» в `README.md`).

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

WORD = {"down": "не отвечает", "warn": "отвечает не тем"}

state = json.load(urllib.request.urlopen(API, timeout=15))
bad = {}
for t in state["targets"]:
    last = t["last"] or {}
    if not last:
        continue                       # ещё ни разу не проверялась
    kind = last.get("state") or ("up" if last.get("ok") else "down")
    if kind != "up":
        bad[t["name"]] = [kind, last.get("error", "нет данных")]

try:
    prev = dict(json.load(open(STATE)))
except Exception:
    prev = {}                          # первый запуск либо файл от старой версии

host = socket.gethostname()
# Пишем и когда цель стала нештатной, и когда сменила одно состояние на другое:
# переход «отвечает не тем» → «не отвечает» важнее самого первого сообщения.
if new := [n for n, (kind, _) in bad.items() if prev.get(n) != kind]:
    notify(f"[{host}] " + "; ".join(f"{n} — {WORD[bad[n][0]]}: {bad[n][1]}"
                                    for n in sorted(new)))
if back := set(prev) - set(bad):
    notify(f"[{host}] снова в порядке: " + ", ".join(sorted(back)))

with open(STATE, "w") as fh:
    json.dump({n: kind for n, (kind, _) in bad.items()}, fh)
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

Если оповещения об оговорках не нужны, оставьте в `bad` только `kind == "down"`.
После обновления с версии без третьего состояния первый запуск пришлёт по одному
сообщению на каждую нештатную цель: формат файла состояния изменился, и старый
скрипт его не поймёт — это разовое.

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

Через админку на `/admin` — перезапускать сервис не нужно, демон подхватывает
изменения в течение секунды. Выключенная галочкой цель перестаёт проверяться,
но сохраняет историю; удаление цели удаляет и её историю.

Правка конфига (`sudo nano /etc/onionwatch/config.json`) нужна только для портов,
интервалов и таймаутов и требует `sudo systemctl restart onionwatch`.

**Обновление кода**

```bash
scp onionwatch.py dashboard.html admin.html admin@<IP>:~/onionwatch/
sudo install -o root -g root -m 0644 ~/onionwatch/onionwatch.py  /opt/onionwatch/
sudo install -o root -g root -m 0644 ~/onionwatch/dashboard.html /opt/onionwatch/
sudo install -o root -g root -m 0644 ~/onionwatch/admin.html     /opt/onionwatch/
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
| У всех целей `general_failure` | в `torrc` нет `ExtendedErrors` — Tor не сообщает причину (раздел 2). Если он там есть, значит адрес действительно не разбирается: проверьте его в админке |
| Не войти в админку, пароль забыт | заведите заново: `sudo -u onionwatch python3 /opt/onionwatch/onionwatch.py --config /etc/onionwatch/config.json --set-admin admin` |
| `Слишком много попыток` при входе | сработала защита от подбора: 8 неудач с адреса, ждать 15 минут либо перезапустить сервис |
| `client_auth_missing` | сервис требует клиентский ключ; onionwatch авторизацию не передаёт — добавьте ключ в `ClientOnionAuthDir` в `torrc` |
| `timeout` у всех целей | увеличьте `timeout` до 90–120 с и снизьте `concurrency`; на слабых VPS цепочки строятся долго |
| Сервис падает с `Read-only file system` | `db_path` вне `/var/lib/onionwatch` — юнит запрещает запись в другие места |
| `Permission denied` при старте | конфиг недоступен пользователю: `sudo chown root:onionwatch /etc/onionwatch/config.json && sudo chmod 640 …` |
| Дашборд пустой, баннер об ошибке API | процесс не запущен либо туннель ведёт не на тот порт: `curl -s 127.0.0.1:8088/api/state` на самом сервере |
| Дашборд пустой, баннера нет | целей ещё нет — заведите их в `/admin`; в логе демона при этом нет строк `UP`/`DOWN` |
| Onion-адрес не открывается, при этом tor работает и `curl 127.0.0.1:8088` даёт `200` | проверьте адрес с самого сервера: `curl --socks5-hostname 127.0.0.1:9050 http://<адрес>.onion/`. Ответ `200` означает, что сервис жив и дело в клиенте (браузер, старый адрес, кэш); ошибка SOCKS назовёт причину, если в `torrc` включён `ExtendedErrors` |
| Свежий onion-адрес не открывается первые минуты | дескриптор публикуется не мгновенно: после рестарта Tor подождите 1–2 минуты |
| Onion-адрес не открывается в обычном браузере | зона `.onion` резолвится только через Tor — нужен Tor Browser |
| `apt update` не видит репозиторий Tor | нет сборки под `noble` — временно поставьте пакет из universe |
| Первые минуты все цели красные | это нормально: первая проверка каждой цели стартует со случайной задержкой, а цепочка строится 5–30 секунд |
| Цель красная, а в Tor Browser открывается | красное значит «не достучались»: смотрите `error_slug` в логе. Если сервис отвечает, но не тем, цель будет жёлтой, а не красной. Разбор — в разделе «Ложная недоступность» в `README.md` |
| Цель жёлтая, «с оговоркой» | сервис на связи, но отдаёт не то, чего ждёт цель: капча, страница анти-DDoS, переехавший адрес. Причина написана прямо в карточке; лечится ожидаемым кодом в настройках цели либо режимом `tcp` |
| Цель то красная, то зелёная без причины | цепочки срываются. Поднимите `attempts` до 4–5 и `timeout` до 90–120 с; в подсказке на ленте видно, со скольких попыток цель отвечает |
| Недоступные цели проверяются дольше интервала | каждая отрабатывает `attempts × timeout + (attempts − 1) × retry_delay`. Снизьте `attempts` или поднимите `check_interval` |

---

## 10. Итоговый чеклист

- [ ] Вход по SSH-ключу, root-логин и пароли отключены
- [ ] `ufw` включён, наружу открыт только SSH
- [ ] `timedatectl` показывает синхронизацию времени
- [ ] `tor@default` активен, `curl --socks5-hostname` возвращает `"IsTor":true`
- [ ] `onionwatch` в статусе `active (running)` и включён в автозапуск
- [ ] В `torrc` включён `ExtendedErrors` — иначе причины сбоев не видны
- [ ] Администратор создан, вход в `/admin` работает, цели заведены
- [ ] `--once` отрабатывает без ошибок `tor_down`
- [ ] Дашборд открывается выбранным способом: SSH-туннель, onion-адрес или nginx
- [ ] Onion-адрес проверен с самого сервера через `curl --socks5-hostname`
- [ ] Таймер оповещений включён и хотя бы раз отработал
- [ ] Настроено резервное копирование базы, если история важна

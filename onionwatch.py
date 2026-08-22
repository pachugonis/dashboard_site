#!/usr/bin/env python3
"""
onionwatch — монитор доступности onion-сервисов (Tor hidden services).

У цели может быть несколько адресов: один обычный (clear) и до десяти onion.
Каждый проверяется отдельно через SOCKS5-порт локального Tor, история пишется
в SQLite, наружу отдаётся веб-дашборд, страница новостей и JSON API. Цели
и новости заводятся в админке (вход по логину и паролю), конфиг задаёт
только инфраструктуру.

Зависимости: только стандартная библиотека Python 3.11+ и запущенный tor.

    python3 onionwatch.py --config config.json              # демон + дашборд
    python3 onionwatch.py --config config.json --once       # один прогон в консоль
    python3 onionwatch.py --config config.json --set-admin admin   # завести админа
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import contextlib
import getpass
import hashlib
import hmac
import http.cookies
import json
import os
import random
import re
import secrets
import sqlite3
import ssl
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
UA = "onionwatch/2.0"          # чем представляется наш собственный веб-сервер

# Чем представляются исходящие проверки. Перед живыми onion-ресурсами почти
# всегда стоит анти-DDoS (EndGame и его клоны), который отвечает 403 или капчей
# всему, что не похоже на Tor Browser: отсутствия Accept-Language уже хватает,
# чтобы посчитать клиента ботом. Отсюда и типовая картинка «в браузере сайт
# открывается, а монитор красный».
#
# Версию стоит обновлять вслед за Tor Browser: у всех его пользователей она
# одинаковая, поэтому отставшая на пару лет строка снова делает нас заметными.
TOR_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0"
BROWSER_HEADERS = (
    # Ровно тот набор и порядок, что шлёт Tor Browser при переходе по ссылке.
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", "gzip, deflate"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
)

# Сбои, которые бывают разовыми: цепочка не собралась, HSDir не ответил,
# сервис придержал нас под нагрузкой. Их имеет смысл повторить. Ответы вроде
# «клиентская авторизация отклонена» повторять незачем — они не изменятся.
RETRY_SLUGS = frozenset({
    "timeout", "connection", "socks_error", "general_failure",
    "net_unreachable", "host_unreachable", "ttl_expired",
    "descriptor_not_found", "intro_failed", "intro_timeout", "rendezvous_failed",
})

# Коды ответа SOCKS5: стандартные (RFC 1928) + расширения Tor (prop304).
# Расширенные коды 0xF0–0xF7 Tor присылает, только если в torrc у SocksPort
# выставлен флаг ExtendedErrors; иначе всё схлопывается в 0x01.
SOCKS_ERRORS = {
    0x01: ("general_failure", "Общий сбой SOCKS-прокси"),
    0x02: ("not_allowed", "Соединение запрещено правилами прокси"),
    0x03: ("net_unreachable", "Сеть недоступна"),
    0x04: ("host_unreachable", "Хост недоступен"),
    0x05: ("refused", "Соединение отклонено"),
    0x06: ("ttl_expired", "TTL истёк"),
    0x07: ("cmd_unsupported", "Команда не поддерживается"),
    0x08: ("atyp_unsupported", "Тип адреса не поддерживается"),
    0xF0: ("descriptor_not_found", "Дескриптор сервиса не найден в HSDir"),
    0xF1: ("descriptor_invalid", "Дескриптор сервиса повреждён"),
    0xF2: ("intro_failed", "Не удалось связаться с introduction point"),
    0xF3: ("rendezvous_failed", "Не удалось построить rendezvous-цепочку"),
    0xF4: ("client_auth_missing", "Нужна клиентская авторизация (ключ не задан)"),
    0xF5: ("client_auth_wrong", "Клиентская авторизация отклонена"),
    0xF6: ("bad_onion_address", "Некорректный onion-адрес"),
    0xF7: ("intro_timeout", "Таймаут на introduction point"),
}

# Параметры scrypt для паролей администраторов (~16 МБ памяти на проверку).
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32, "maxmem": 64 * 1024 * 1024}

ONION_V3 = re.compile(r"^[a-z2-7]{56}\.onion$")
NAME_RE = re.compile(r"^[^/\\\x00-\x1f]{1,64}$")
MAX_ONIONS = 10               # сколько onion-зеркал можно завести одной цели
MAX_IMAGE = 5 * 1024 * 1024
# Картинка приезжает в теле как base64, а он на треть длиннее самих байтов:
# предел тела обязан быть выше MAX_IMAGE * 4/3, иначе картинку предельного
# размера отвергнет не проверка формата, а вот эта — с ошибкой не по делу.
MAX_BODY = 8 * 1024 * 1024
MAX_NEWS_TEXT = 4000          # новость — заметка под картинкой, а не статья
MAX_SOURCE_URL = 500          # ссылка на первоисточник новости
NEWS_PER_PAGE = 10            # сколько новостей на одной странице ленты
NEWS_ADMIN_LIMIT = 500        # сколько новостей видит админка — там они правятся списком

# Растр обрезает и уменьшает браузер, сюда приходит готовый квадрат.
# Сервер обязан перепроверить формат: доверять Content-Type от клиента нельзя.
# SVG — исключение: он вектор, обрезать в нём по пикселям нечего, и приходит он
# как есть. Зато это XML, который браузер исполняет, — его проверяет check_svg.
IMAGE_MAGIC = {
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
}
SVG_TYPE = "image/svg+xml"
DATA_URL = re.compile(r"data:(image/(?:png|jpeg|svg\+xml));base64,([A-Za-z0-9+/=\s]+)")

# Внутрь SVG пускаем только то, что рисует. Всё, что умеет исполняться или
# ходить наружу, — отказ целиком: вычистить такой файл надёжно всё равно не
# выйдет, а лежит он в нашем же источнике и открывается прямой ссылкой.
SVG_BANNED = (
    (re.compile(r"<\s*(?:script|foreignObject|iframe|embed|object|handler)\b", re.I),
     "В SVG есть исполняемые элементы"),
    (re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.I),
     "В SVG есть DTD — так собирают XXE и «миллиард смешков»"),
    (re.compile(r"<\?xml-stylesheet\b", re.I), "В SVG есть внешняя таблица стилей"),
    (re.compile(r"\son[a-z]+\s*=", re.I), "В SVG есть обработчики событий"),
    (re.compile(r"javascript\s*:", re.I), "В SVG есть javascript-ссылка"),
    (re.compile(r"url\(\s*['\"]?\s*(?:[a-z][a-z0-9+.-]*:|//)", re.I),
     "В SVG есть ссылка наружу в стилях"),
)
# Ссылаться можно на кусок этого же файла или на вшитый в него растр.
SVG_REF = re.compile(r"""(?:xlink:)?(?:href|src)\s*=\s*(["'])(.*?)\1""", re.I | re.S)
SVG_SAFE_REF = re.compile(r"(?:#|data:image/(?:png|jpeg);base64,)", re.I)


class ProxyDown(Exception):
    """SOCKS-порт Tor не принимает соединения."""


class SocksError(Exception):
    def __init__(self, code: int):
        self.code = code
        self.slug, self.message = SOCKS_ERRORS.get(code, ("socks_error", f"Код SOCKS 0x{code:02X}"))
        super().__init__(f"{self.message} (0x{code:02X})")


class Invalid(ValueError):
    """Некорректные данные от пользователя — отдаём как 400, а не как 500."""


# --------------------------------------------------------------------------
# Конфигурация
# --------------------------------------------------------------------------

@dataclass
class Address:
    """Один адрес сервиса. У цели их может быть несколько — это зеркала.

    Обычный адрес и onion различаются только именем хоста, поэтому вид (kind)
    не хранится, а выводится из него: ошибиться и завести onion как clear
    нельзя в принципе. Ходим мы и туда и туда через тот же SOCKS Tor: для
    обычного адреса это просто выход через exit-узел.
    """
    url: str
    id: int = 0
    # разобранный url
    kind: str = "onion"         # onion | clear
    host: str = ""
    port: int = 80
    path: str = "/"
    tls: bool = False

    def __post_init__(self) -> None:
        u = urllib.parse.urlsplit(self.url if "://" in self.url else "http://" + self.url)
        self.tls = u.scheme == "https"
        self.host = u.hostname or ""
        self.port = u.port or (443 if self.tls else 80)
        self.path = u.path or "/"
        if u.query:
            self.path += "?" + u.query
        if not self.host:
            raise Invalid(f"Не удалось разобрать адрес {self.url!r}")
        self.kind = "onion" if self.host.endswith(".onion") else "clear"

    @property
    def label(self) -> str:
        """Короткая подпись для карточки: хэш onion в неё целиком не влезает."""
        h = self.host
        if len(h) > 22 and h.endswith(".onion"):
            h = h[:8] + "…" + h[-14:]
        return h if self.port in (80, 443) else f"{h}:{self.port}"


@dataclass
class Target:
    name: str
    addresses: list[Address] = field(default_factory=list)
    interval: int = 300
    timeout: float = 60.0
    expect_text: str | None = None
    mode: str = "http"          # http | tcp
    note: str = ""
    id: int = 0
    enabled: bool = True
    has_image: bool = False
    updated_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.addresses:
            raise Invalid(f"{self.name}: у цели нет ни одного адреса")

    @property
    def primary(self) -> Address:
        """Главный адрес: обычный, если он есть, иначе первый onion.

        Порядок задаётся при сохранении, здесь он уже готов. По этому адресу
        считаются тайминги в ленте — чтобы полоска не прыгала между зеркалами.
        """
        return self.addresses[0]

    @property
    def url(self) -> str:
        return self.primary.url


@dataclass
class Config:
    tor_socks: tuple[str, int] = ("127.0.0.1", 9050)
    listen: tuple[str, int] = ("127.0.0.1", 8088)
    db_path: str = "onionwatch.db"
    interval: int = 300
    timeout: float = 60.0
    concurrency: int = 6
    retention_days: int = 30
    isolate_circuits: bool = True
    attempts: int = 3                # попыток до вердикта «недоступен»
    retry_delay: float = 20.0        # пауза между попытками
    circuit_ttl: float = 1800.0      # сколько держимся за одну цепочку на цель
    user_agent: str = TOR_BROWSER_UA
    require_login: bool = False      # закрыть логином и сам дашборд, не только админку
    session_hours: int = 12
    seed_targets: list[dict[str, Any]] = field(default_factory=list)


def _hostport(value: str, default_port: int) -> tuple[str, int]:
    if ":" in value:
        host, _, port = value.rpartition(":")
        return host or "127.0.0.1", int(port)
    return value, default_port


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    cfg = Config()
    cfg.tor_socks = _hostport(raw.get("tor_socks", "127.0.0.1:9050"), 9050)
    cfg.listen = _hostport(raw.get("listen", "127.0.0.1:8088"), 8088)
    cfg.db_path = raw.get("db_path", cfg.db_path)
    cfg.interval = int(raw.get("check_interval", cfg.interval))
    cfg.timeout = float(raw.get("timeout", cfg.timeout))
    cfg.concurrency = int(raw.get("concurrency", cfg.concurrency))
    cfg.retention_days = int(raw.get("retention_days", cfg.retention_days))
    cfg.isolate_circuits = bool(raw.get("isolate_circuits", True))
    cfg.attempts = max(1, min(10, int(raw.get("attempts", cfg.attempts))))
    cfg.retry_delay = max(0.0, float(raw.get("retry_delay", cfg.retry_delay)))
    cfg.circuit_ttl = max(0.0, float(raw.get("circuit_ttl", cfg.circuit_ttl)))
    cfg.user_agent = str(raw.get("user_agent") or cfg.user_agent)
    cfg.require_login = bool(raw.get("require_login", False))
    cfg.session_hours = int(raw.get("session_hours", cfg.session_hours))
    # targets в конфиге больше не нужны: они живут в базе и заводятся в админке.
    # Если они там есть, при первом запуске (пустая таблица) их импортируем.
    cfg.seed_targets = list(raw.get("targets", []))

    if not cfg.db_path.startswith("/"):
        cfg.db_path = os.path.join(os.path.dirname(os.path.abspath(path)), cfg.db_path)
    return cfg


# --------------------------------------------------------------------------
# Валидация целей
# --------------------------------------------------------------------------

def clean_url(raw: str) -> str:
    """Проверяет один адрес и приводит его к каноническому виду.

    Бросает Invalid с текстом для UI: адрес — единственное поле формы, ошибку
    в котором нельзя заметить постфактум. Опечатка в onion — это не сломанный
    адрес, а адрес другого сервиса, и найти её потом уже не по чему.
    """
    url = raw.strip()
    if "://" not in url:
        url = "http://" + url
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https", "tcp"):
        raise Invalid(f"Схема {u.scheme!r} не поддерживается: только http, https или tcp")
    try:
        host, port = u.hostname, u.port
    except ValueError as e:
        raise Invalid(f"Некорректный адрес: {e}") from e
    if not host:
        raise Invalid(f"В адресе {raw.strip()!r} нет имени хоста")
    if not host.isascii():
        # Ровно та ошибка, которую даёт адрес-заглушка кириллицей: Tor такой
        # хост не разберёт и ответит общим сбоем SOCKS.
        raise Invalid("Имя хоста содержит не-ASCII символы — это не onion-адрес")
    if host.endswith(".onion") and not ONION_V3.match(host):
        raise Invalid("Это не похоже на onion-адрес v3: 56 символов a–z и 2–7, затем .onion. "
                      "Проверьте адрес — ошибка в одном символе указывает на другой сервис")
    if u.scheme == "tcp" and not port:
        raise Invalid("Для tcp:// нужно указать порт, например tcp://адрес.onion:22")
    return url


def clean_addresses(data: dict[str, Any]) -> list[str]:
    """Собирает адреса цели: обычный (не больше одного) и onion-зеркала.

    Возвращает их в порядке проверки, первым — главный. Вид адреса определяет
    имя хоста, а не поле формы: onion, вписанный в строку обычного адреса,
    останется onion, а не превратится в него по недоразумению.
    """
    raw: list[str] = []
    if data.get("clear"):
        raw.append(str(data["clear"]))
    onions = data.get("onions") or []
    if isinstance(onions, str):
        onions = re.split(r"[,\s]+", onions)
    raw += [str(x) for x in onions]
    # Старая форма записи (и targets[] из конфига): один адрес в поле url.
    if not any(x.strip() for x in raw) and data.get("url"):
        raw = [str(data["url"])]

    clear: list[str] = []
    onion: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not item.strip():
            continue
        url = clean_url(item)
        key = url.lower()
        if key in seen:
            raise Invalid(f"Адрес {url} указан дважды")
        seen.add(key)
        (onion if Address(url).kind == "onion" else clear).append(url)

    if not clear and not onion:
        raise Invalid("Укажите хотя бы один адрес сервиса")
    if len(clear) > 1:
        raise Invalid("Обычный адрес может быть только один — остальные зеркала должны быть onion")
    if len(onion) > MAX_ONIONS:
        raise Invalid(f"Onion-адресов не больше {MAX_ONIONS}, а указано {len(onion)}")
    return clear + onion


def clean_target(data: dict[str, Any], cfg: Config) -> tuple[dict[str, Any], list[str]]:
    """Приводит форму админки к полям таблицы. Бросает Invalid с текстом для UI."""
    # Адреса разбираем первыми: имя в форме подставляется из них, и на пустой
    # форме «укажите адрес» объясняет больше, чем «имя: от 1 до 64 символов».
    urls = clean_addresses(data)
    name = str(data.get("name", "")).strip()
    if not NAME_RE.match(name):
        raise Invalid("Имя: от 1 до 64 символов, без «/» и «\\»")

    mode = str(data.get("mode")
               or ("tcp" if urls[0].startswith("tcp://") else "http"))
    if mode not in ("http", "tcp"):
        raise Invalid("Режим: http или tcp")

    def opt_num(key: str, lo: float, hi: float) -> float | None:
        v = data.get(key)
        if v in (None, "", "auto"):
            return None
        try:
            v = float(v)
        except (TypeError, ValueError) as e:
            raise Invalid(f"Поле {key}: нужно число") from e
        if not lo <= v <= hi:
            raise Invalid(f"Поле {key}: допустимо от {lo:g} до {hi:g}")
        return v

    interval = opt_num("interval", 30, 86400)
    timeout = opt_num("timeout", 5, 600)

    expect_text = (data.get("expect_text") or "").strip() or None
    if expect_text and len(expect_text) > 200:
        raise Invalid("Искомая строка слишком длинная (максимум 200 символов)")

    note = (data.get("note") or "").strip()[:300]

    row = {
        "name": name, "url": urls[0], "mode": mode,
        "interval": int(interval) if interval else None,
        "timeout": timeout,
        "expect_text": expect_text, "note": note,
        "enabled": 1 if data.get("enabled", True) else 0,
    }
    # Финальная проверка: цель должна собираться.
    row_to_target(row | {"id": 0}, cfg, [Address(u) for u in urls])
    return row, urls


def clean_source(raw: Any) -> str | None:
    """Ссылка на первоисточник новости: http(s) и ничего больше.

    Схему проверяем до разбора: `javascript:` и `data:` в ленте становятся
    ссылкой, по которой читатель кликнет, поэтому отказ должен быть здесь,
    а не в экранировании на странице. Дальше адрес идёт через тот же разбор,
    что и адреса целей, — он же проверит onion v3 и отсечёт кириллицу.
    """
    text = str(raw or "").strip()
    if not text:
        return None
    if len(text) > MAX_SOURCE_URL:
        raise Invalid(f"Ссылка на источник длиннее {MAX_SOURCE_URL} символов")
    # Схема — всё до первого двоеточия, но только если оно стоит перед первым
    # слэшем и за ним не число: в «example.test:8080/x» это порт, а не схема,
    # и такую запись clean_url принимает, дописывая http://.
    head = text.split("/", 1)[0]
    if ":" in head:
        scheme, _, rest = head.partition(":")
        if scheme.lower() not in ("http", "https") and not rest.isdigit():
            raise Invalid(f"Ссылка на источник: схема {scheme.lower()!r} не годится, "
                          f"нужен http или https")
    return clean_url(text)


def clean_news(data: dict[str, Any]) -> tuple[str, str | None]:
    """Проверяет новость: текст и ссылку на источник. Бросает Invalid для UI.

    Текст хранится как есть, без разметки: страница новостей экранирует его
    и сама разбивает по пустым строкам на абзацы. Картинка к тексту
    необязательна — новость без неё остаётся читаемой, а вот без слов нет.
    Источник тоже необязателен: своя новость ни на кого не ссылается.
    """
    text = str(data.get("text", "")).replace("\r\n", "\n").strip()
    if not text:
        raise Invalid("Текст новости пуст — напишите хотя бы строку")
    if len(text) > MAX_NEWS_TEXT:
        raise Invalid(f"Текст новости длиннее {MAX_NEWS_TEXT} символов "
                      f"(сейчас {len(text)}) — сократите его")
    return text, clean_source(data.get("source"))


def check_svg(blob: bytes) -> None:
    """Пускает дальше только рисующее подмножество SVG. Бросает Invalid с текстом для UI."""
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Invalid("SVG не читается как текст в UTF-8") from e
    for pattern, message in SVG_BANNED:
        if pattern.search(text):
            raise Invalid(message)
    for _, ref in SVG_REF.findall(text):
        if not SVG_SAFE_REF.match(ref.strip()):
            raise Invalid(f"В SVG есть ссылка наружу: {ref.strip()[:40]}")
    # Разбираем как XML: браузер сделает то же самое и покажет пустоту, если
    # файл битый или без пространства имён SVG.
    try:
        root = ET.fromstring(blob)
    except ET.ParseError as e:
        raise Invalid("SVG не разбирается как XML — файл повреждён") from e
    if root.tag != "{http://www.w3.org/2000/svg}svg":
        raise Invalid("Корень файла — не <svg> из пространства имён SVG")


def parse_image(data_url: str) -> tuple[bytes, str]:
    """Разбирает data-URL от админки в (байты, тип). Бросает Invalid с текстом для UI."""
    m = DATA_URL.fullmatch(str(data_url).strip())
    if not m:
        raise Invalid("Изображение должно быть data-URL в формате PNG, JPEG или SVG")
    ctype = m.group(1)
    try:
        blob = base64.b64decode(m.group(2), validate=False)
    except (binascii.Error, ValueError) as e:
        raise Invalid("Изображение не декодируется из base64") from e
    if not blob:
        raise Invalid("Изображение пустое")
    if len(blob) > MAX_IMAGE:
        raise Invalid(f"Изображение больше {MAX_IMAGE / (1024 * 1024):g} МБ — уменьшите его")
    if ctype == SVG_TYPE:
        check_svg(blob)
    # Проверяем сигнатуру: заявленный тип должен совпадать с содержимым.
    elif not blob.startswith(IMAGE_MAGIC[ctype]):
        raise Invalid("Содержимое файла не похоже на заявленный формат")
    return blob, ctype


def _field(r: Any, key: str, default: Any = None) -> Any:
    """Строка базы или словарь из формы — второй набор ключей беднее."""
    try:
        return r[key]
    except (KeyError, IndexError):
        return default


def row_to_target(r: Any, cfg: Config, addresses: list[Address]) -> Target:
    return Target(
        name=r["name"],
        addresses=addresses,
        interval=int(r["interval"] or cfg.interval),
        timeout=float(r["timeout"] or cfg.timeout),
        expect_text=r["expect_text"],
        mode=r["mode"] or "http",
        note=r["note"] or "",
        id=int(r["id"] or 0),
        enabled=bool(r["enabled"]),
        has_image=_field(r, "image") is not None,
        updated_at=float(_field(r, "updated_at") or 0.0),
    )


# --------------------------------------------------------------------------
# SOCKS5-клиент поверх asyncio (без сторонних библиотек)
# --------------------------------------------------------------------------

async def socks5_open(
    proxy: tuple[str, int],
    host: str,
    port: int,
    username: str | None = None,
    password: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Открывает поток к host:port через SOCKS5. Имя хоста резолвит прокси (socks5h)."""
    try:
        reader, writer = await asyncio.open_connection(*proxy)
    except OSError as e:
        raise ProxyDown(f"SOCKS-порт Tor {proxy[0]}:{proxy[1]} недоступен ({e.strerror or e})") from e
    try:
        methods = b"\x00\x02" if username else b"\x00"
        writer.write(b"\x05" + bytes([len(methods)]) + methods)
        await writer.drain()

        ver, method = await reader.readexactly(2)
        if ver != 0x05:
            raise ConnectionError("Прокси ответил не по протоколу SOCKS5")
        if method == 0x02:
            u = (username or "").encode()[:255]
            p = (password or "").encode()[:255]
            writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            await writer.drain()
            _, status = await reader.readexactly(2)
            if status != 0x00:
                raise ConnectionError("SOCKS-прокси отклонил авторизацию")
        elif method != 0x00:
            raise ConnectionError("SOCKS-прокси не предложил поддерживаемый метод авторизации")

        addr = host.encode("ascii")
        writer.write(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + port.to_bytes(2, "big"))
        await writer.drain()

        head = await reader.readexactly(4)
        if head[1] != 0x00:
            raise SocksError(head[1])
        atyp = head[3]
        if atyp == 0x01:
            await reader.readexactly(4)
        elif atyp == 0x03:
            ln = (await reader.readexactly(1))[0]
            await reader.readexactly(ln)
        elif atyp == 0x04:
            await reader.readexactly(16)
        await reader.readexactly(2)
        return reader, writer
    except BaseException:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


def _tls_context() -> ssl.SSLContext:
    # У onion-сервисов почти всегда самоподписанные сертификаты: домен уже
    # аутентифицирован самим адресом сервиса, проверка PKI здесь не нужна.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Circuits:
    """Пароль в SOCKS-авторизации выбирает цепочку.

    При IsolateSOCKSAuth (включён у Tor по умолчанию) Tor держит отдельную
    цепочку на каждую пару логин/пароль. Случайный пароль на каждую проверку
    означал бы шесть новых узлов и новый rendezvous каждые пять минут — самую
    медленную и хрупкую операцию в Tor. Постоянная строка на цель даёт то же,
    что открытая вкладка браузера: проверки идут по уже построенной цепочке.

    Сколько цепочка живёт на самом деле, решает Tor: после MaxCircuitDirtiness
    (по умолчанию 10 минут) он выдаст новую даже под тем же паролем. Поэтому
    circuit_ttl задаёт лишь верхнюю границу, а не гарантию.
    """

    def __init__(self, ttl: float):
        self.ttl = ttl
        self._creds: dict[str, tuple[str, float]] = {}

    def password(self, name: str) -> str:
        password, born = self._creds.get(name, ("", 0.0))
        if not password or time.time() - born >= self.ttl:
            password = secrets.token_hex(8)
            self._creds[name] = (password, time.time())
        return password

    def drop(self, name: str) -> None:
        """Цепочка подвела или цель изменилась — следующая проверка возьмёт новую."""
        self._creds.pop(name, None)


def _header(head: bytes, name: str) -> str:
    """Значение заголовка из уже прочитанного блока, в нижнем регистре."""
    want = name.encode().lower()
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.strip().lower() == want:
            return value.strip().decode("latin-1").lower()
    return ""


class Unpack:
    """Разжимает тело ответа по кускам.

    Раз мы просим gzip, как браузер, — обязаны его понимать, иначе expect_text
    перестанет находиться. Распаковка потоковая: строку ищем на лету, не
    дожидаясь конца передачи.
    """

    def __init__(self, encoding: str):
        self.encoding = encoding
        self.started = False
        if encoding == "gzip":
            self.dec: Any = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif encoding == "deflate":
            self.dec = zlib.decompressobj(zlib.MAX_WBITS)
        else:
            self.dec = None

    def __call__(self, chunk: bytes) -> bytes:
        if self.dec is None:
            return chunk
        try:
            out = self.dec.decompress(chunk)
        except zlib.error as e:
            if self.started or self.encoding != "deflate":
                raise ValueError(f"ответ не разжимается ({self.encoding})") from e
            # Часть серверов шлёт deflate «как есть», без zlib-заголовка.
            self.dec = zlib.decompressobj(-zlib.MAX_WBITS)
            try:
                out = self.dec.decompress(chunk)
            except zlib.error as e2:
                raise ValueError("ответ не разжимается (deflate)") from e2
        self.started = True
        return out


# --------------------------------------------------------------------------
# Проверка одной цели
# --------------------------------------------------------------------------

def circuit_key(t: Target, a: Address) -> str:
    """Ключ изоляции цепочки: свой у каждого адреса, а не у цели.

    Зеркала — разные сервисы с точки зрения Tor, и общая цепочка означала бы,
    что упавшее зеркало тянет за собой живое.
    """
    return f"ow-{t.name}#{a.id}"


async def check_address(cfg: Config, t: Target, a: Address,
                        circuits: Circuits | None = None) -> dict[str, Any]:
    """Возвращает результат проверки одного адреса: ok, фаза сбоя, тайминги."""
    res: dict[str, Any] = {
        "target": t.name, "addr_id": a.id, "url": a.url,
        "ts": time.time(), "ok": False, "phase": "circuit",
        "status": None, "connect_ms": None, "ttfb_ms": None, "total_ms": None,
        "error": None, "error_slug": None, "attempts": 1,
    }
    creds: tuple[str | None, str | None] = (None, None)
    if cfg.isolate_circuits:
        # Отдельная цепочка на каждый адрес (Tor IsolateSOCKSAuth): зависший
        # сервис не тянет за собой остальные. Пароль постоянный в пределах
        # circuit_ttl — иначе каждая проверка строила бы цепочку заново.
        key = circuit_key(t, a)
        creds = (key, circuits.password(key) if circuits else secrets.token_hex(8))

    t0 = time.perf_counter()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            socks5_open(cfg.tor_socks, a.host, a.port, *creds), timeout=t.timeout
        )
        res["connect_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        deadline = t0 + t.timeout

        if t.mode == "tcp":
            res.update(ok=True, phase="done")
        else:
            res["phase"] = "request"
            if a.tls:
                await asyncio.wait_for(
                    writer.start_tls(_tls_context(), server_hostname=a.host),
                    timeout=max(1.0, deadline - time.perf_counter()),
                )
            # Порт в Host опускаем только если он совпадает со схемой:
            # браузер поступает так же, а строгий вход по имени иначе ответит 404.
            authority = a.host if a.port == (443 if a.tls else 80) else f"{a.host}:{a.port}"
            lines = [f"GET {a.path} HTTP/1.1", f"Host: {authority}",
                     f"User-Agent: {cfg.user_agent}"]
            lines += [f"{k}: {v}" for k, v in BROWSER_HEADERS]
            lines.append("Connection: close")
            writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
            await writer.drain()

            res["phase"] = "response"
            head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=max(1.0, deadline - time.perf_counter())
            )
            res["ttfb_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = status_line.split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit():
                raise ValueError("Сервис ответил не по HTTP")
            res["status"] = int(parts[1])

            # Ответил по HTTP — значит, доступен, каким бы код ни был. За
            # onion-ресурсами почти всегда стоит анти-DDoS: 503 значит
            # «работает, но придерживает нас», а редирект — что нас встретила
            # капча. И то и другое в браузере открывается, и разбирать коды
            # ответа на «те» и «не те» здесь не по чему.
            ok = True
            # Единственное содержательное условие, и то по желанию: если задана
            # строка, её отсутствие в успешном ответе значит, что отвечает не
            # тот сервис. У кода не 2xx тела с ней и не должно быть — там нас
            # встретила заглушка, а не сервис, и её отсутствие ни о чём не говорит.
            if t.expect_text and 200 <= res["status"] < 300:
                res["phase"] = "body"
                needle = t.expect_text.encode()
                unpack = Unpack(_header(head, "Content-Encoding"))
                body, raw = b"", 0
                while raw < 256 * 1024 and len(body) < 4 * 1024 * 1024:
                    chunk = await asyncio.wait_for(
                        reader.read(16384), timeout=max(1.0, deadline - time.perf_counter())
                    )
                    if not chunk:
                        break
                    raw += len(chunk)
                    body += unpack(chunk)
                    if needle in body:
                        break
                if needle not in body:
                    ok = False
                    res["error_slug"] = "text_missing"
                    res["error"] = f"В ответе нет строки {t.expect_text!r}"
            res["ok"] = ok
            res["phase"] = "done" if ok else res["phase"]

    except ProxyDown as e:
        res["error_slug"], res["error"] = "tor_down", str(e)
    except SocksError as e:
        res["error_slug"], res["error"] = e.slug, str(e)
    except asyncio.TimeoutError:
        res["error_slug"] = "timeout"
        res["error"] = f"Таймаут {t.timeout:.0f} с на фазе «{res['phase']}»"
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            ssl.SSLError, ValueError, OSError) as e:
        res["error_slug"] = "connection"
        res["error"] = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
    except Exception as e:  # проверка всегда должна вернуть строку результата
        res["error_slug"] = "internal"
        res["error"] = f"Внутренняя ошибка проверки: {type(e).__name__}: {e}"
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=5)
            except Exception:
                pass

    # Состояний два: до сервиса достучались или нет. Красным остаётся только
    # то, до чего мы не дошли, — цепочка, таймаут до ответа, мёртвый tor.
    res["state"] = "up" if res["ok"] else "down"
    res["total_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return res


def retryable(res: dict[str, Any]) -> bool:
    """Стоит ли повторить проверку, или ответ уже окончательный."""
    return res["error_slug"] in RETRY_SLUGS


async def check_with_retry(cfg: Config, t: Target, a: Address,
                           circuits: Circuits | None = None,
                           sem: asyncio.Semaphore | None = None) -> dict[str, Any]:
    """Помечает адрес недоступным только после нескольких неудачных попыток.

    Одна проверка через Tor срывается и на совершенно живом сервисе: цепочка
    не собралась, дескриптор не нашёлся, анти-DDoS придержал под нагрузкой.
    Ретрай отделяет такой разовый сбой от настоящей недоступности — иначе
    моргнувшая цепочка красит цель в красное до следующего цикла.

    Семафор берём на каждую попытку отдельно: держать его во время паузы
    значило бы занимать место в очереди, ничего не делая.
    """
    guard: Any = sem if sem is not None else contextlib.nullcontext()
    total = max(1, cfg.attempts)
    res: dict[str, Any] = {}
    for attempt in range(1, total + 1):
        async with guard:
            res = await check_address(cfg, t, a, circuits)
        res["attempts"] = attempt
        if res["ok"]:
            break
        again = retryable(res)
        if again and circuits is not None:
            # Подвела цепочка — следующая попытка берёт новую.
            circuits.drop(circuit_key(t, a))
        if not again or attempt == total:
            break
        await asyncio.sleep(cfg.retry_delay)
    return res


def rollup(t: Target, results: list[dict[str, Any]]) -> dict[str, Any]:
    """Сводит проверки всех адресов цели в одну запись истории.

    Цель доступна, пока отвечает хоть одно зеркало: адреса на то и заводят,
    чтобы падение одного не было падением сервиса. Тайминги в ленту берём у
    первого доступного адреса — а первый в списке всегда главный, так что
    полоска не прыгает между зеркалами, пока главное работает.
    """
    alive = [r for r in results if r["ok"]]
    row = dict(alive[0] if alive else results[0])
    row["target"] = t.name
    row["ok"] = bool(alive)
    row["state"] = "up" if alive else "down"
    row["alive"] = len(alive)      # в базу не идёт: нужно логу и --once
    row["addrs"] = len(results)
    return row


# --------------------------------------------------------------------------
# Хранилище
# --------------------------------------------------------------------------

class Store:
    def __init__(self, path: str):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.targets_rev = 0     # растёт при любом изменении списка целей
        with self.lock:
            self.db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    ts REAL NOT NULL,
                    ok INTEGER NOT NULL,
                    phase TEXT,
                    status INTEGER,
                    connect_ms REAL,
                    ttfb_ms REAL,
                    total_ms REAL,
                    error_slug TEXT,
                    error TEXT,
                    attempts INTEGER,
                    state TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_checks_target_ts ON checks(target, ts DESC);

                -- url здесь — главный адрес цели; полный список живёт
                -- в addresses. Дублируется он ради старых баз и запросов,
                -- пишется всегда из первого адреса и разъехаться не может.
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    url TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'http',
                    interval INTEGER,
                    timeout REAL,
                    expect_text TEXT,
                    note TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    image BLOB,
                    image_type TEXT
                );

                CREATE TABLE IF NOT EXISTS addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    position INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_addresses_target
                    ON addresses(target_id, position);

                -- Только последняя проверка каждого адреса: на карточке нужно
                -- «доступен или нет», а история и аптайм считаются по цели.
                CREATE TABLE IF NOT EXISTS addr_last (
                    addr_id INTEGER PRIMARY KEY,
                    ts REAL NOT NULL,
                    state TEXT NOT NULL,
                    status INTEGER,
                    connect_ms REAL,
                    ttfb_ms REAL,
                    total_ms REAL,
                    attempts INTEGER
                );

                -- Новости: картинка и текст к ней. К целям отношения не имеют
                -- и живут своей лентой, поэтому и таблица отдельная. Колонки
                -- картинки те же, что у targets, — работа с ними общая.
                CREATE TABLE IF NOT EXISTS news (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    text TEXT NOT NULL,
                    source TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    image BLOB,
                    image_type TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_news_created ON news(created_at DESC);

                CREATE TABLE IF NOT EXISTS admins (
                    login TEXT PRIMARY KEY,
                    salt BLOB NOT NULL,
                    hash BLOB NOT NULL,
                    created_at REAL NOT NULL,
                    last_login REAL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    login TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )
            # База, созданная до появления картинок, этих колонок не имеет.
            have = {r["name"] for r in self.db.execute("PRAGMA table_info(targets)")}
            for column, decl in (("image", "BLOB"), ("image_type", "TEXT")):
                if column not in have:
                    self.db.execute(f"ALTER TABLE targets ADD COLUMN {column} {decl}")
            # База, заведённая до появления ссылки на первоисточник, этой
            # колонки не имеет — у старых новостей источника просто нет.
            have = {r["name"] for r in self.db.execute("PRAGMA table_info(news)")}
            if "source" not in have:
                self.db.execute("ALTER TABLE news ADD COLUMN source TEXT")
            # Так же и с историей проверок: попытка была всегда одна, а состояний
            # было два. Старые записи разносим по новой шкале — иначе аптайм за
            # неделю считался бы по половине колонки.
            have = {r["name"] for r in self.db.execute("PRAGMA table_info(checks)")}
            for column, decl in (("attempts", "INTEGER"), ("state", "TEXT")):
                if column not in have:
                    self.db.execute(f"ALTER TABLE checks ADD COLUMN {column} {decl}")
            if "state" not in have:
                self.db.execute(
                    "UPDATE checks SET state = CASE WHEN ok THEN 'up' ELSE 'down' END")
            # Состояний было три, стало два. «С оговоркой» значило «сервис на
            # связи, но отдал не то» и в аптайм шло как доступность — поэтому
            # старые записи переезжают в 'up', и цифры от этого не меняются.
            if self.db.execute("SELECT 1 FROM checks WHERE state='warn' LIMIT 1").fetchone():
                self.db.execute("UPDATE checks SET state='up' WHERE state='warn'")
            # База, созданная до появления зеркал, хранит единственный адрес
            # в самой цели: переносим его в таблицу адресов как главный.
            for r in self.db.execute(
                    "SELECT id, url FROM targets"
                    " WHERE id NOT IN (SELECT target_id FROM addresses)").fetchall():
                self.db.execute(
                    "INSERT INTO addresses (target_id, url, position) VALUES (?,?,0)",
                    (r["id"], r["url"]))
            self.db.commit()

    # -- проверки ----------------------------------------------------------

    def add(self, r: dict[str, Any]) -> None:
        with self.lock:
            self.db.execute(
                "INSERT INTO checks (target, ts, ok, phase, status, connect_ms, ttfb_ms,"
                " total_ms, error_slug, error, attempts, state)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["target"], r["ts"], int(r["ok"]), r["phase"], r["status"], r["connect_ms"],
                 r["ttfb_ms"], r["total_ms"], r["error_slug"], r["error"],
                 r.get("attempts", 1), r.get("state") or ("up" if r["ok"] else "down")),
            )
            self.db.commit()

    def prune(self, days: int) -> int:
        cutoff = time.time() - days * 86400
        with self.lock:
            cur = self.db.execute("DELETE FROM checks WHERE ts < ?", (cutoff,))
            self.db.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
            self.db.commit()
            return cur.rowcount

    def history(self, target: str, limit: int = 60) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT ts, ok, state, status, connect_ms, ttfb_ms, error_slug, error, attempts"
                " FROM checks WHERE target=? ORDER BY ts DESC LIMIT ?", (target, limit)
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def summary(self, target: str, window_s: float) -> dict[str, Any]:
        since = time.time() - window_s
        with self.lock:
            # Аптайм — доля проверок, в которых сервис был на связи хотя бы по
            # одному адресу. Тайминги считаем по тем же проверкам: у недоступной
            # цели времени ответа нет, и оно только испортило бы среднее.
            row = self.db.execute(
                "SELECT COUNT(*) n, SUM(state<>'down') alive,"
                " AVG(CASE WHEN state<>'down' THEN ttfb_ms END) ttfb,"
                " AVG(CASE WHEN state<>'down' THEN connect_ms END) conn"
                " FROM checks WHERE target=? AND ts>=?", (target, since)
            ).fetchone()
        n = row["n"] or 0
        alive = row["alive"] or 0
        return {
            "checks": n,
            "uptime": round(100.0 * alive / n, 2) if n else None,
            "avg_ttfb_ms": round(row["ttfb"], 0) if row["ttfb"] else None,
            "avg_circuit_ms": round(row["conn"], 0) if row["conn"] else None,
        }

    # -- цели --------------------------------------------------------------

    def list_targets(self, cfg: Config, enabled_only: bool = False) -> list[Target]:
        q = "SELECT * FROM targets"
        if enabled_only:
            q += " WHERE enabled=1"
        q += " ORDER BY id"
        with self.lock:
            rows = self.db.execute(q).fetchall()
            addr_rows = self.db.execute(
                "SELECT * FROM addresses ORDER BY target_id, position, id").fetchall()
        by_target: dict[int, list[Address]] = {}
        for a in addr_rows:
            try:
                by_target.setdefault(a["target_id"], []).append(
                    Address(url=a["url"], id=a["id"]))
            except ValueError as e:
                print(f"! адрес {a['url']!r} пропущен: {e}", file=sys.stderr, flush=True)
        out = []
        for r in rows:
            try:
                out.append(row_to_target(r, cfg, by_target.get(r["id"], [])))
            except ValueError as e:
                print(f"! цель {r['name']!r} пропущена: {e}", file=sys.stderr, flush=True)
        return out

    def add_target(self, row: dict[str, Any], urls: list[str]) -> int:
        now = time.time()
        with self.lock:
            if self.db.execute("SELECT 1 FROM targets WHERE name=?", (row["name"],)).fetchone():
                raise Invalid(f"Цель с именем {row['name']!r} уже есть")
            cur = self.db.execute(
                "INSERT INTO targets (name, url, mode, interval, timeout,"
                " expect_text, note, enabled, created_at, updated_at)"
                " VALUES (:name,:url,:mode,:interval,:timeout,"
                " :expect_text,:note,:enabled,:now,:now)", row | {"now": now})
            tid = int(cur.lastrowid)
            self._write_addresses(tid, urls)
            self.db.commit()
            self.targets_rev += 1
            return tid

    def update_target(self, tid: int, row: dict[str, Any], urls: list[str]) -> None:
        with self.lock:
            old = self.db.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
            if not old:
                raise Invalid("Цель не найдена")
            clash = self.db.execute(
                "SELECT 1 FROM targets WHERE name=? AND id<>?", (row["name"], tid)).fetchone()
            if clash:
                raise Invalid(f"Цель с именем {row['name']!r} уже есть")
            self.db.execute(
                "UPDATE targets SET name=:name, url=:url, mode=:mode, interval=:interval,"
                " timeout=:timeout, expect_text=:expect_text,"
                " note=:note, enabled=:enabled, updated_at=:now WHERE id=:id",
                row | {"id": tid, "now": time.time()})
            self._write_addresses(tid, urls)
            if old["name"] != row["name"]:
                # История привязана к имени — переносим, иначе графики обнулятся.
                self.db.execute("UPDATE checks SET target=? WHERE target=?",
                                (row["name"], old["name"]))
            self.db.commit()
            self.targets_rev += 1

    def _write_addresses(self, tid: int, urls: list[str]) -> None:
        """Приводит список адресов цели к заданному, вызывается под self.lock.

        Уцелевшие адреса сохраняют свой id: к нему привязано их последнее
        состояние, и пересоздание строк обнуляло бы карточку при каждой правке
        соседнего поля.
        """
        old = {r["url"]: r["id"] for r in self.db.execute(
            "SELECT id, url FROM addresses WHERE target_id=?", (tid,))}
        for pos, url in enumerate(urls):
            aid = old.pop(url, None)
            if aid is None:
                self.db.execute(
                    "INSERT INTO addresses (target_id, url, position) VALUES (?,?,?)",
                    (tid, url, pos))
            else:
                self.db.execute("UPDATE addresses SET position=? WHERE id=?", (pos, aid))
        for aid in old.values():
            self.db.execute("DELETE FROM addresses WHERE id=?", (aid,))
            self.db.execute("DELETE FROM addr_last WHERE addr_id=?", (aid,))

    def delete_target(self, tid: int) -> str:
        with self.lock:
            row = self.db.execute("SELECT name FROM targets WHERE id=?", (tid,)).fetchone()
            if not row:
                raise Invalid("Цель не найдена")
            self._write_addresses(tid, [])
            self.db.execute("DELETE FROM targets WHERE id=?", (tid,))
            self.db.execute("DELETE FROM checks WHERE target=?", (row["name"],))
            self.db.commit()
            self.targets_rev += 1
            return row["name"]

    # -- состояние адресов -------------------------------------------------

    def set_addr_state(self, res: dict[str, Any]) -> None:
        with self.lock:
            self.db.execute(
                "INSERT INTO addr_last (addr_id, ts, state, status, connect_ms, ttfb_ms,"
                " total_ms, attempts) VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(addr_id) DO UPDATE SET ts=excluded.ts, state=excluded.state,"
                " status=excluded.status, connect_ms=excluded.connect_ms,"
                " ttfb_ms=excluded.ttfb_ms, total_ms=excluded.total_ms,"
                " attempts=excluded.attempts",
                (res["addr_id"], res["ts"], res["state"], res["status"], res["connect_ms"],
                 res["ttfb_ms"], res["total_ms"], res.get("attempts", 1)))
            self.db.commit()

    def addr_states(self) -> dict[int, dict[str, Any]]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM addr_last").fetchall()
        return {int(r["addr_id"]): dict(r) for r in rows}

    # -- картинки ----------------------------------------------------------
    # У целей и у новостей картинка устроена одинаково: блоб, его тип и
    # updated_at. Имя таблицы в запрос попадает только отсюда, из двух пар
    # методов ниже, — снаружи его подставить некуда.

    def _put_image(self, table: str, oid: int, blob: bytes | None,
                   ctype: str | None) -> None:
        # updated_at двигаем всегда: он попадает в URL картинки как версия,
        # иначе браузеры будут показывать старую из кэша.
        with self.lock:
            cur = self.db.execute(
                f"UPDATE {table} SET image=?, image_type=?, updated_at=? WHERE id=?",
                (blob, ctype, time.time(), oid))
            if not cur.rowcount:
                raise Invalid("Запись не найдена")
            self.db.commit()

    def _get_image(self, table: str, oid: int) -> tuple[bytes, str] | None:
        with self.lock:
            row = self.db.execute(
                f"SELECT image, image_type FROM {table} WHERE id=?", (oid,)).fetchone()
        if not row or row["image"] is None:
            return None
        return row["image"], row["image_type"] or "image/png"

    def set_image(self, tid: int, blob: bytes, ctype: str) -> None:
        with self.lock:
            self._put_image("targets", tid, blob, ctype)
            self.targets_rev += 1

    def clear_image(self, tid: int) -> None:
        with self.lock:
            self._put_image("targets", tid, None, None)
            self.targets_rev += 1

    def image(self, tid: int) -> tuple[bytes, str] | None:
        return self._get_image("targets", tid)

    def seed_targets(self, cfg: Config) -> int:
        """Разовый импорт targets[] из конфига, пока таблица пуста."""
        with self.lock:
            if self.db.execute("SELECT 1 FROM targets LIMIT 1").fetchone():
                return 0
        added = 0
        for item in cfg.seed_targets:
            try:
                self.add_target(*clean_target(item, cfg))
                added += 1
            except Invalid as e:
                print(f"! цель {item.get('name')!r} из конфига не импортирована: {e}",
                      file=sys.stderr, flush=True)
        return added

    # -- новости -----------------------------------------------------------

    def count_news(self) -> int:
        with self.lock:
            return int(self.db.execute("SELECT COUNT(*) c FROM news").fetchone()["c"])

    def list_news(self, limit: int = NEWS_PER_PAGE, offset: int = 0) -> list[dict[str, Any]]:
        """Лента для страницы новостей: свежие сверху, без самих блобов."""
        with self.lock:
            rows = self.db.execute(
                "SELECT id, text, source, created_at, updated_at,"
                " image IS NOT NULL AS has_image FROM news"
                " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                (limit, offset)).fetchall()
        return [{"id": int(r["id"]), "text": r["text"], "source": r["source"],
                 "created_at": r["created_at"], "updated_at": r["updated_at"],
                 "has_image": bool(r["has_image"]),
                 "image_v": int(r["updated_at"])} for r in rows]

    def add_news(self, text: str, source: str | None = None) -> int:
        now = time.time()
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO news (text, source, created_at, updated_at) VALUES (?,?,?,?)",
                (text, source, now, now))
            self.db.commit()
            return int(cur.lastrowid)

    def update_news(self, nid: int, text: str, source: str | None = None) -> None:
        with self.lock:
            # created_at не трогаем: правка опечатки не должна поднимать
            # новость обратно наверх ленты.
            cur = self.db.execute(
                "UPDATE news SET text=?, source=?, updated_at=? WHERE id=?",
                (text, source, time.time(), nid))
            if not cur.rowcount:
                raise Invalid("Новость не найдена")
            self.db.commit()

    def delete_news(self, nid: int) -> None:
        with self.lock:
            cur = self.db.execute("DELETE FROM news WHERE id=?", (nid,))
            if not cur.rowcount:
                raise Invalid("Новость не найдена")
            self.db.commit()

    def set_news_image(self, nid: int, blob: bytes, ctype: str) -> None:
        self._put_image("news", nid, blob, ctype)

    def clear_news_image(self, nid: int) -> None:
        self._put_image("news", nid, None, None)

    def news_image(self, nid: int) -> tuple[bytes, str] | None:
        return self._get_image("news", nid)

    # -- администраторы и сессии ------------------------------------------

    def admin_count(self) -> int:
        with self.lock:
            return int(self.db.execute("SELECT COUNT(*) c FROM admins").fetchone()["c"])

    def set_admin(self, login: str, password: str) -> None:
        login = login.strip()
        if not 1 <= len(login) <= 64:
            raise Invalid("Логин: от 1 до 64 символов")
        if len(password) < 10:
            raise Invalid("Пароль: минимум 10 символов")
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
        with self.lock:
            self.db.execute(
                "INSERT INTO admins (login, salt, hash, created_at) VALUES (?,?,?,?)"
                " ON CONFLICT(login) DO UPDATE SET salt=excluded.salt, hash=excluded.hash",
                (login, salt, digest, time.time()))
            self.db.commit()

    def check_password(self, login: str, password: str) -> bool:
        with self.lock:
            row = self.db.execute("SELECT * FROM admins WHERE login=?", (login,)).fetchone()
        if not row:
            # Считаем впустую, чтобы по времени ответа нельзя было перебирать логины.
            hashlib.scrypt(password.encode(), salt=b"0" * 16, **SCRYPT)
            return False
        digest = hashlib.scrypt(password.encode(), salt=row["salt"], **SCRYPT)
        if not hmac.compare_digest(digest, row["hash"]):
            return False
        with self.lock:
            self.db.execute("UPDATE admins SET last_login=? WHERE login=?", (time.time(), login))
            self.db.commit()
        return True

    def open_session(self, login: str, hours: int) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            self.db.execute(
                "INSERT INTO sessions (token_hash, login, created_at, expires_at) VALUES (?,?,?,?)",
                (_token_hash(token), login, now, now + hours * 3600))
            self.db.commit()
        return token

    def session_login(self, token: str) -> str | None:
        if not token:
            return None
        with self.lock:
            row = self.db.execute(
                "SELECT login, expires_at FROM sessions WHERE token_hash=?",
                (_token_hash(token),)).fetchone()
        if not row or row["expires_at"] < time.time():
            return None
        return row["login"]

    def close_session(self, token: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(token),))
            self.db.commit()

    def close_all_sessions(self, login: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM sessions WHERE login=?", (login,))
            self.db.commit()


def _token_hash(token: str) -> str:
    # В базе лежит только хэш: утечка файла не даёт живых сессий.
    return hashlib.sha256(token.encode()).hexdigest()


# --------------------------------------------------------------------------
# Планировщик
# --------------------------------------------------------------------------

class Monitor:
    def __init__(self, cfg: Config, store: Store):
        self.cfg = cfg
        self.store = store
        self.sem = asyncio.Semaphore(cfg.concurrency)
        self.circuits = Circuits(cfg.circuit_ttl)
        self.loop: asyncio.AbstractEventLoop | None = None
        self.last: dict[str, dict[str, Any]] = {}
        self.running: set[str] = set()
        self.started_at = time.time()
        self.targets: dict[str, Target] = {}
        self.due: dict[str, float] = {}
        self._rev = -1

    # -- список целей ------------------------------------------------------

    def sync_targets(self, force: bool = False) -> None:
        """Подхватывает изменения из админки без перезапуска демона."""
        if not force and self._rev == self.store.targets_rev:
            return
        self._rev = self.store.targets_rev
        fresh = {t.name: t for t in self.store.list_targets(self.cfg, enabled_only=True)}
        now = time.time()

        def addrs(t: Target) -> list[tuple[int, str]]:
            return [(a.id, a.url) for a in t.addresses]

        for name, t in fresh.items():
            old = self.targets.get(name)
            if old is None or addrs(old) != addrs(t) or old.mode != t.mode:
                # Новая цель или переписанные адреса — проверяем сразу, а старые
                # цепочки к ней отношения не имеют.
                self.due[name] = now
                for a in (old.addresses if old else []) + t.addresses:
                    self.circuits.drop(circuit_key(t, a))
            elif name not in self.due:
                self.due[name] = now
        for name in list(self.due):
            if name not in fresh:
                self.due.pop(name, None)
                self.last.pop(name, None)
                gone = self.targets.get(name)
                for a in (gone.addresses if gone else []):
                    self.circuits.drop(circuit_key(gone, a))
        self.targets = fresh

    # -- прогон ------------------------------------------------------------

    async def run_check(self, t: Target) -> dict[str, Any]:
        if t.name in self.running:
            return self.last.get(t.name, {})
        self.running.add(t.name)
        try:
            # Все адреса цели проверяются в одном заходе: карточка показывает их
            # рядом, и данные в ней должны быть одного времени. Параллельность
            # ограничивает общий семафор — он берётся внутри, на каждую попытку.
            results = await asyncio.gather(*(
                check_with_retry(self.cfg, t, a, self.circuits, self.sem)
                for a in t.addresses))
        finally:
            self.running.discard(t.name)
        for res in results:
            self.store.set_addr_state(res)
        roll = rollup(t, results)
        self.store.add(roll)
        self.last[t.name] = roll
        mark = "UP  " if roll["state"] == "up" else "DOWN"
        detail = f"адресов на связи: {roll['alive']} из {roll['addrs']}"
        tries = roll.get("attempts", 1)
        if tries > 1:
            detail += f" · попыток: {tries}"
        print(f"[{time.strftime('%H:%M:%S')}] {mark} {t.name:<24} "
              f"{roll['total_ms']:>7.0f} ms  {detail}", flush=True)
        return roll

    async def _guarded(self, t: Target) -> None:
        try:
            await self.run_check(t)
        except Exception as e:  # проверка не должна ронять планировщик
            print(f"! ошибка планировщика для {t.name}: {e}", file=sys.stderr, flush=True)

    async def _loop_prune(self) -> None:
        while True:
            await asyncio.sleep(3600)
            removed = self.store.prune(self.cfg.retention_days)
            if removed:
                print(f"[db] удалено старых записей: {removed}", flush=True)

    async def serve(self) -> None:
        """Один цикл на все цели: список может меняться прямо во время работы."""
        self.loop = asyncio.get_running_loop()
        asyncio.create_task(self._loop_prune())
        # Первый прогон разносим по времени, чтобы не бить в Tor всеми целями разом.
        self.sync_targets(force=True)
        spread = min(20.0, self.cfg.interval)
        for name in self.due:
            self.due[name] = time.time() + random.uniform(0, spread)
        while True:
            self.sync_targets()
            now = time.time()
            for name, t in list(self.targets.items()):
                if name not in self.running and self.due.get(name, 0) <= now:
                    self.due[name] = now + t.interval * random.uniform(0.9, 1.1)
                    asyncio.create_task(self._guarded(t))
            await asyncio.sleep(1)

    def request_check(self, name: str) -> bool:
        """Вызывается из потока HTTP-сервера."""
        self.sync_targets()
        t = self.targets.get(name)
        if not t or self.loop is None:
            return False
        self.due[name] = time.time() + t.interval
        asyncio.run_coroutine_threadsafe(self._guarded(t), self.loop)
        return True

    def tor_alive(self) -> bool:
        import socket
        try:
            with socket.create_connection(self.cfg.tor_socks, timeout=3) as s:
                s.sendall(b"\x05\x01\x00")
                return s.recv(2)[:1] == b"\x05"
        except OSError:
            return False

    def state(self) -> dict[str, Any]:
        self.sync_targets()
        addr_states = self.store.addr_states()
        out = []
        for t in self.targets.values():
            last = self.last.get(t.name)
            if last is None:
                rows = self.store.history(t.name, 1)
                last = rows[-1] if rows else None
            out.append({
                "id": t.id,
                "name": t.name,
                "url": t.url,
                "host": t.primary.host,
                "label": t.primary.label,
                "port": t.primary.port,
                "addresses": [{
                    "id": a.id,
                    "kind": a.kind,
                    "url": a.url,
                    "host": a.host,
                    "label": a.label,
                    "last": addr_states.get(a.id),
                } for a in t.addresses],
                "mode": t.mode,
                "note": t.note,
                "has_image": t.has_image,
                "image_v": int(t.updated_at),
                "interval": t.interval,
                "checking": t.name in self.running,
                "last": last,
                "day": self.store.summary(t.name, 86400),
                "week": self.store.summary(t.name, 7 * 86400),
                "history": self.store.history(t.name, 60),
            })
        # У записей, сделанных до появления поля state, его нет.
        marks = [("pending" if not x["last"] else
                  "down" if (x["last"].get("state") or ("up" if x["last"].get("ok") else "down"))
                  == "down" else "up")
                 for x in out]
        return {
            "generated_at": time.time(),
            "started_at": self.started_at,
            "tor_ok": self.tor_alive(),
            "tor_socks": f"{self.cfg.tor_socks[0]}:{self.cfg.tor_socks[1]}",
            "up": marks.count("up"),
            "down": marks.count("down"),
            "pending": marks.count("pending"),
            "total": len(out),
            "targets": out,
        }


# --------------------------------------------------------------------------
# HTTP-интерфейс
# --------------------------------------------------------------------------

COOKIE = "ow_session"


class LoginGuard:
    """Тормозит перебор пароля: счётчик неудач на IP."""

    LIMIT, WINDOW, PENALTY = 8, 900.0, 1.0

    def __init__(self) -> None:
        self.fails: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def blocked(self, ip: str) -> float:
        with self.lock:
            hits = [t for t in self.fails.get(ip, []) if t > time.time() - self.WINDOW]
            self.fails[ip] = hits
            if len(hits) < self.LIMIT:
                return 0.0
            return self.WINDOW - (time.time() - hits[0])

    def fail(self, ip: str) -> None:
        with self.lock:
            self.fails.setdefault(ip, []).append(time.time())

    def reset(self, ip: str) -> None:
        with self.lock:
            self.fails.pop(ip, None)


def make_handler(monitor: Monitor):
    store = monitor.store
    cfg = monitor.cfg
    guard = LoginGuard()

    class Handler(BaseHTTPRequestHandler):
        server_version = UA
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # тихий лог
            pass

        # -- примитивы ----------------------------------------------------

        def _send(self, code: int, body: bytes, ctype: str, cookie: str | None = None,
                  extra: dict[str, str] | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            if not (extra or {}).get("Cache-Control"):
                self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            if not (extra or {}).get("Content-Security-Policy"):
                self.send_header("Content-Security-Policy",
                                 "default-src 'none'; img-src 'self' data:; "
                                 "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                                 "connect-src 'self'; form-action 'none'; frame-ancestors 'none'")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, payload: Any, cookie: str | None = None) -> None:
            self._send(code, json.dumps(payload, ensure_ascii=False).encode(),
                       "application/json; charset=utf-8", cookie)

        def _page(self, filename: str) -> None:
            try:
                with open(os.path.join(HERE, filename), "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(404, f"{filename} not found next to onionwatch.py".encode(),
                           "text/plain; charset=utf-8")

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return {}
            if length > MAX_BODY:
                # Называем оба числа: чаще всего предел оказывается меньше
                # ожидаемого потому, что onionwatch.py на сервере старее страниц.
                raise Invalid(f"Запрос на {length // 1024} КБ не принят, "
                              f"предел этой версии — {MAX_BODY // 1024} КБ")
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise Invalid(f"Тело запроса не разобрано как JSON: {e}") from e
            if not isinstance(data, dict):
                raise Invalid("Ожидался JSON-объект")
            return data

        # -- сессия -------------------------------------------------------

        def _token(self) -> str:
            raw = self.headers.get("Cookie")
            if not raw:
                return ""
            try:
                jar = http.cookies.SimpleCookie(raw)
            except http.cookies.CookieError:
                return ""
            morsel = jar.get(COOKIE)
            return morsel.value if morsel else ""

        def _login(self) -> str | None:
            return store.session_login(self._token())

        def _secure(self) -> bool:
            return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

        def _cookie(self, token: str | None) -> str:
            parts = [f"{COOKIE}={token or ''}", "Path=/", "HttpOnly", "SameSite=Strict"]
            if self._secure():
                parts.append("Secure")
            parts.append(f"Max-Age={cfg.session_hours * 3600}" if token else "Max-Age=0")
            return "; ".join(parts)

        def _require_admin(self) -> str | None:
            """Логин или None; при None ответ клиенту уже отправлен."""
            login = self._login()
            if not login:
                self._json(401, {"error": "Нужен вход в админку"})
                return None
            # Заголовок нельзя выставить кросс-сайтовой формой — это защита от CSRF
            # в дополнение к SameSite=Strict.
            if self.headers.get("X-Requested-With") != "onionwatch":
                self._json(403, {"error": "Запрос без метки X-Requested-With отклонён"})
                return None
            return login

        def _public_ok(self) -> bool:
            """Пускать ли на дашборд без входа."""
            return not cfg.require_login or bool(self._login())

        def _client_ip(self) -> str:
            fwd = self.headers.get("X-Forwarded-For", "")
            return fwd.split(",")[0].strip() or self.client_address[0]

        # -- маршруты -----------------------------------------------------

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            try:
                if path in ("/", "/index.html"):
                    if not self._public_ok():
                        return self._page("admin.html")
                    return self._page("dashboard.html")
                if path in ("/admin", "/admin.html"):
                    return self._page("admin.html")
                if path in ("/news", "/news.html"):
                    return self._page("news.html")

                if path == "/api/session":
                    login = self._login()
                    return self._json(200, {
                        "authed": bool(login),
                        "login": login,
                        "has_admin": store.admin_count() > 0,
                        "require_login": cfg.require_login,
                    })

                if path == "/api/state":
                    if not self._public_ok():
                        return self._json(401, {"error": "Нужен вход"})
                    return self._json(200, monitor.state())

                if path.startswith("/api/targets/") and path.endswith("/image"):
                    if not self._public_ok():
                        return self._json(401, {"error": "Нужен вход"})
                    return self._serve_image(
                        store.image(self._path_id(path[:-len("/image")])))

                if path == "/api/news":
                    if not self._public_ok():
                        return self._json(401, {"error": "Нужен вход"})
                    return self._json(200, self._news_page())

                if path.startswith("/api/news/") and path.endswith("/image"):
                    if not self._public_ok():
                        return self._json(401, {"error": "Нужен вход"})
                    return self._serve_image(
                        store.news_image(self._path_id(path[:-len("/image")])))

                if path.startswith("/api/targets/") and path.endswith("/history"):
                    if not self._public_ok():
                        return self._json(401, {"error": "Нужен вход"})
                    name = urllib.parse.unquote(path.split("/")[3])
                    return self._json(200, {"target": name,
                                            "history": store.history(name, 500)})

                if path == "/api/admin/news":
                    if not self._require_admin():
                        return None
                    # Админке лента отдаётся целиком: править можно любую
                    # новость, а не только ту, что попала на первую страницу.
                    return self._json(200, {"news": store.list_news(NEWS_ADMIN_LIMIT),
                                            "total": store.count_news()})

                if path == "/api/admin/targets":
                    if not self._require_admin():
                        return None
                    rows = [{
                        "id": t.id, "name": t.name, "url": t.url, "mode": t.mode,
                        "addresses": [{"id": a.id, "kind": a.kind, "url": a.url}
                                      for a in t.addresses],
                        "interval": t.interval, "timeout": t.timeout,
                        "expect_text": t.expect_text,
                        "note": t.note, "enabled": t.enabled, "has_image": t.has_image,
                    } for t in store.list_targets(cfg)]
                    return self._json(200, {"targets": rows,
                                            "defaults": {"interval": cfg.interval,
                                                         "timeout": cfg.timeout},
                                            "max_onions": MAX_ONIONS})

                return self._json(404, {"error": "Такого маршрута нет"})
            except Invalid as e:
                return self._json(400, {"error": str(e)})

        def do_HEAD(self):
            self.do_GET()

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            try:
                if path == "/api/login":
                    return self._login_route()
                if path == "/api/logout":
                    token = self._token()
                    if token:
                        store.close_session(token)
                    return self._json(200, {"ok": True}, self._cookie(None))

                if path.startswith("/api/targets/") and path.endswith("/check"):
                    if not self._public_ok():
                        return self._json(401, {"error": "Нужен вход"})
                    name = urllib.parse.unquote(path.split("/")[3])
                    if monitor.request_check(name):
                        return self._json(202, {"queued": name})
                    return self._json(404, {"error": f"Цель {name} не найдена"})

                if path == "/api/admin/targets":
                    if not self._require_admin():
                        return None
                    data = self._body()
                    row, urls = clean_target(data, cfg)
                    tid = store.add_target(row, urls)
                    self._apply_image(tid, data)
                    monitor.sync_targets()
                    return self._json(201, {"id": tid})

                if path == "/api/admin/news":
                    if not self._require_admin():
                        return None
                    data = self._body()
                    text, source = clean_news(data)
                    # Картинку разбираем до вставки: иначе битый файл оставил бы
                    # в ленте опубликованную новость и ошибку в форме.
                    image = self._image_of(data)
                    nid = store.add_news(text, source)
                    if image:
                        store.set_news_image(nid, *image)
                    return self._json(201, {"id": nid})

                if path == "/api/admin/password":
                    login = self._require_admin()
                    if not login:
                        return None
                    data = self._body()
                    if not store.check_password(login, str(data.get("current", ""))):
                        return self._json(403, {"error": "Текущий пароль неверен"})
                    store.set_admin(login, str(data.get("password", "")))
                    store.close_all_sessions(login)   # переподключиться придётся везде
                    return self._json(200, {"ok": True}, self._cookie(None))

                return self._json(404, {"error": "Такого маршрута нет"})
            except Invalid as e:
                return self._json(400, {"error": str(e)})

        def do_PUT(self):
            path = urllib.parse.urlsplit(self.path).path
            try:
                if path.startswith("/api/admin/targets/"):
                    if not self._require_admin():
                        return None
                    tid = self._path_id(path)
                    data = self._body()
                    row, urls = clean_target(data, cfg)
                    store.update_target(tid, row, urls)
                    self._apply_image(tid, data)
                    monitor.sync_targets()
                    return self._json(200, {"ok": True})

                if path.startswith("/api/admin/news/"):
                    if not self._require_admin():
                        return None
                    nid = self._path_id(path)
                    data = self._body()
                    text, source = clean_news(data)
                    image = self._image_of(data)
                    store.update_news(nid, text, source)
                    if image:
                        store.set_news_image(nid, *image)
                    elif data.get("image_clear"):
                        store.clear_news_image(nid)
                    return self._json(200, {"ok": True})
                return self._json(404, {"error": "Такого маршрута нет"})
            except Invalid as e:
                return self._json(400, {"error": str(e)})

        def do_DELETE(self):
            path = urllib.parse.urlsplit(self.path).path
            try:
                if path.startswith("/api/admin/targets/"):
                    if not self._require_admin():
                        return None
                    name = store.delete_target(self._path_id(path))
                    monitor.sync_targets()
                    return self._json(200, {"deleted": name})

                if path.startswith("/api/admin/news/"):
                    if not self._require_admin():
                        return None
                    nid = self._path_id(path)
                    store.delete_news(nid)
                    return self._json(200, {"deleted": nid})
                return self._json(404, {"error": "Такого маршрута нет"})
            except Invalid as e:
                return self._json(400, {"error": str(e)})

        def _serve_image(self, found: tuple[bytes, str] | None) -> None:
            """Отдаёт картинку цели или новости — они хранятся одинаково."""
            if not found:
                return self._json(404, {"error": "Изображения нет"})
            blob, ctype = found
            etag = '"%s"' % hashlib.sha256(blob).hexdigest()[:24]
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # Дашборд перерисовывается каждые 15 секунд — картинку он должен
            # брать из кэша, а не тащить заново. Политика здесь своя и глухая:
            # SVG браузер исполняет, а этот адрес открывается прямой ссылкой без
            # пароля — общая политика страниц разрешает скрипты, эта не разрешает
            # ничего. Инлайновые стили оставлены: без них SVG теряет вид.
            self._send(200, blob, ctype, extra={
                "ETag": etag,
                "Cache-Control": "private, max-age=300",
                "Content-Security-Policy":
                    "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            })

        def _news_page(self) -> dict[str, Any]:
            """Одна страница ленты: свежие сверху, NEWS_PER_PAGE штук за раз."""
            total = store.count_news()
            pages = max(1, -(-total // NEWS_PER_PAGE))
            raw = urllib.parse.parse_qs(
                urllib.parse.urlsplit(self.path).query).get("page", ["1"])[0]
            try:
                page = int(raw)
            except ValueError as e:
                raise Invalid("Номер страницы должен быть числом") from e
            # Ссылку из закладок, оставшуюся за краем ленты, показываем как
            # последнюю страницу, а не как пустоту: новости сдвигаются вниз
            # по мере появления новых, и такая ссылка стареет сама собой.
            page = min(max(page, 1), pages)
            return {
                "news": store.list_news(NEWS_PER_PAGE, (page - 1) * NEWS_PER_PAGE),
                "page": page, "pages": pages, "total": total,
                "per_page": NEWS_PER_PAGE,
            }

        def _image_of(self, data: dict[str, Any]) -> tuple[bytes, str] | None:
            """Картинка из тела запроса, если её прислали."""
            raw = data.get("image")
            return parse_image(raw) if raw else None

        def _apply_image(self, tid: int, data: dict[str, Any]) -> None:
            image = self._image_of(data)
            if image:
                store.set_image(tid, *image)
            elif data.get("image_clear"):
                store.clear_image(tid)

        def _path_id(self, path: str) -> int:
            try:
                return int(path.rsplit("/", 1)[1])
            except (IndexError, ValueError) as e:
                raise Invalid("Не разобран идентификатор в адресе") from e

        def _login_route(self) -> None:
            ip = self._client_ip()
            wait = guard.blocked(ip)
            if wait > 0:
                return self._json(429, {"error": f"Слишком много попыток. "
                                                 f"Подождите {int(wait / 60) + 1} мин"})
            data = self._body()
            login = str(data.get("login", "")).strip()
            password = str(data.get("password", ""))
            if not login or not password:
                return self._json(400, {"error": "Введите логин и пароль"})
            if not store.check_password(login, password):
                guard.fail(ip)
                time.sleep(LoginGuard.PENALTY)
                return self._json(401, {"error": "Неверный логин или пароль"})
            guard.reset(ip)
            token = store.open_session(login, cfg.session_hours)
            return self._json(200, {"ok": True, "login": login}, self._cookie(token))

    return Handler


# --------------------------------------------------------------------------
# Точка входа
# --------------------------------------------------------------------------

async def run_once(cfg: Config, store: Store) -> int:
    monitor = Monitor(cfg, store)
    monitor.loop = asyncio.get_running_loop()
    monitor.sync_targets(force=True)
    targets = list(monitor.targets.values())
    if not targets:
        print("В базе нет ни одной включённой цели — заведите их в админке.", file=sys.stderr)
        return 2
    results = await asyncio.gather(*(monitor.run_check(t) for t in targets))
    down = [r for r in results if r["state"] == "down"]
    partial = [r for r in results if r["state"] == "up" and r["alive"] < r["addrs"]]
    print(f"\nДоступно {len(results) - len(down)} из {len(results)}")
    # В консоли причина сбоя остаётся: она нужна тому, кто пришёл разбираться,
    # а на дашборде — только «доступен или нет».
    for r in partial:
        print(f"  ~ {r['target']}: на связи {r['alive']} из {r['addrs']} адресов")
    for r in down:
        print(f"  ✗ {r['target']}: {r['error'] or 'ни один адрес не ответил'}")
    return 1 if down else 0


def open_store(path: str) -> Store:
    """Открывает базу, объясняя проблемы с правами по-человечески."""
    try:
        return Store(path)
    except sqlite3.OperationalError as e:
        directory = os.path.dirname(path) or "."
        user = getpass.getuser()
        print(
            f"База {path} не открылась на запись: {e}\n"
            f"Процесс работает от пользователя {user!r}. Записывать нужно и в саму базу,\n"
            f"и в каталог рядом с ней: в режиме WAL SQLite создаёт там файлы -wal и -shm.\n"
            f"Посмотрите, кому принадлежат каталог и файлы:\n"
            f"  ls -ld {directory} {path}*\n"
            f"Если владелец не {user!r}, поправьте:\n"
            f"  sudo chown -R onionwatch:onionwatch {directory}\n"
            f"  sudo chmod 0750 {directory}",
            file=sys.stderr)
        raise SystemExit(2) from e


def set_admin_interactive(store: Store, login: str) -> int:
    print(f"Пароль для администратора {login!r} (минимум 10 символов).")
    password = getpass.getpass("Пароль: ")
    if password != getpass.getpass("Ещё раз: "):
        print("Пароли не совпали.", file=sys.stderr)
        return 2
    try:
        store.set_admin(login, password)
    except Invalid as e:
        print(f"{e}", file=sys.stderr)
        return 2
    store.close_all_sessions(login)
    print(f"Готово. Вход в админку: /admin, логин {login!r}.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Монитор доступности onion-сервисов")
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--once", action="store_true", help="один прогон и выход (для cron/CI)")
    ap.add_argument("--no-web", action="store_true", help="только проверки, без дашборда")
    ap.add_argument("--set-admin", metavar="ЛОГИН",
                    help="создать администратора или сменить ему пароль и выйти")
    args = ap.parse_args()

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"Конфиг не прочитан: {e}", file=sys.stderr)
        return 2

    store = open_store(cfg.db_path)

    if args.set_admin:
        return set_admin_interactive(store, args.set_admin)

    imported = store.seed_targets(cfg)
    if imported:
        print(f"Из конфига импортировано целей: {imported}. "
              f"Дальше правьте их в админке — в конфиге они больше не нужны.", flush=True)

    if args.once:
        return asyncio.run(run_once(cfg, store))

    monitor = Monitor(cfg, store)
    if not monitor.tor_alive():
        print(f"Внимание: SOCKS-порт Tor {cfg.tor_socks[0]}:{cfg.tor_socks[1]} не отвечает. "
              f"Запустите tor или поправьте tor_socks в конфиге.", file=sys.stderr)
    if store.admin_count() == 0:
        print(f"Администратора ещё нет. Создайте его:\n"
              f"  python3 {os.path.basename(__file__)} --config {args.config} --set-admin admin",
              file=sys.stderr, flush=True)

    if not args.no_web:
        httpd = ThreadingHTTPServer(cfg.listen, make_handler(monitor))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        print(f"Дашборд: http://{cfg.listen[0]}:{cfg.listen[1]}/  "
              f"(админка /admin, база: {cfg.db_path})", flush=True)

    try:
        asyncio.run(monitor.serve())
    except KeyboardInterrupt:
        print("\nОстановлено.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

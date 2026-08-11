#!/usr/bin/env python3
"""
onionwatch — монитор доступности onion-сервисов (Tor hidden services).

Проверяет каждый адрес через SOCKS5-порт локального Tor, пишет историю
в SQLite и отдаёт веб-дашборд + JSON API. Цели заводятся в админке
(вход по логину и паролю), конфиг задаёт только инфраструктуру.

Зависимости: только стандартная библиотека Python 3.11+ и запущенный tor.

    python3 onionwatch.py --config config.json              # демон + дашборд
    python3 onionwatch.py --config config.json --once       # один прогон в консоль
    python3 onionwatch.py --config config.json --set-admin admin   # завести админа
"""

from __future__ import annotations

import argparse
import asyncio
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
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
UA = "onionwatch/2.0"

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
MAX_BODY = 64 * 1024


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
class Target:
    name: str
    url: str
    interval: int = 300
    timeout: float = 60.0
    expect_status: list[int] = field(default_factory=lambda: [200])
    expect_text: str | None = None
    mode: str = "http"          # http | tcp
    note: str = ""
    id: int = 0
    enabled: bool = True
    # разобранный url
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
            raise Invalid(f"{self.name}: не удалось разобрать адрес {self.url!r}")

    @property
    def label(self) -> str:
        h = self.host
        if len(h) > 22 and h.endswith(".onion"):
            h = h[:8] + "…" + h[-14:]
        return h


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

def clean_target(data: dict[str, Any], cfg: Config) -> dict[str, Any]:
    """Приводит форму админки к полям таблицы. Бросает Invalid с текстом для UI."""
    name = str(data.get("name", "")).strip()
    if not NAME_RE.match(name):
        raise Invalid("Имя: от 1 до 64 символов, без «/» и «\\»")

    url = str(data.get("url", "")).strip()
    if not url:
        raise Invalid("Укажите адрес сервиса")
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
        raise Invalid("В адресе нет имени хоста")
    if not host.isascii():
        # Ровно та ошибка, которую даёт адрес-заглушка кириллицей: Tor такой
        # хост не разберёт и ответит общим сбоем SOCKS.
        raise Invalid("Имя хоста содержит не-ASCII символы — это не onion-адрес")
    if host.endswith(".onion") and not ONION_V3.match(host):
        raise Invalid("Это не похоже на onion-адрес v3: 56 символов a–z и 2–7, затем .onion. "
                      "Проверьте адрес — ошибка в одном символе указывает на другой сервис")
    if u.scheme == "tcp" and not port:
        raise Invalid("Для tcp:// нужно указать порт, например tcp://адрес.onion:22")

    mode = str(data.get("mode") or ("tcp" if u.scheme == "tcp" else "http"))
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

    raw_status = data.get("expect_status") or [200]
    if isinstance(raw_status, str):
        raw_status = [p for p in re.split(r"[,\s]+", raw_status.strip()) if p]
    try:
        expect_status = sorted({int(s) for s in raw_status})
    except (TypeError, ValueError) as e:
        raise Invalid("Ожидаемые коды: числа через запятую, например 200, 301") from e
    if not expect_status or any(not 100 <= s <= 599 for s in expect_status):
        raise Invalid("Ожидаемые коды должны быть в диапазоне 100–599")

    expect_text = (data.get("expect_text") or "").strip() or None
    if expect_text and len(expect_text) > 200:
        raise Invalid("Искомая строка слишком длинная (максимум 200 символов)")

    note = (data.get("note") or "").strip()[:300]

    row = {
        "name": name, "url": url, "mode": mode,
        "interval": int(interval) if interval else None,
        "timeout": timeout,
        "expect_status": json.dumps(expect_status),
        "expect_text": expect_text, "note": note,
        "enabled": 1 if data.get("enabled", True) else 0,
    }
    # Финальная проверка: цель должна собираться.
    row_to_target(row | {"id": 0}, cfg)
    return row


def row_to_target(r: Any, cfg: Config) -> Target:
    return Target(
        name=r["name"],
        url=r["url"],
        interval=int(r["interval"] or cfg.interval),
        timeout=float(r["timeout"] or cfg.timeout),
        expect_status=json.loads(r["expect_status"] or "[200]"),
        expect_text=r["expect_text"],
        mode=r["mode"] or "http",
        note=r["note"] or "",
        id=int(r["id"] or 0),
        enabled=bool(r["enabled"]),
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


# --------------------------------------------------------------------------
# Проверка одной цели
# --------------------------------------------------------------------------

async def check_target(cfg: Config, t: Target) -> dict[str, Any]:
    """Возвращает результат проверки: ok, фаза сбоя, коды и тайминги."""
    res: dict[str, Any] = {
        "target": t.name, "ts": time.time(), "ok": False, "phase": "circuit",
        "status": None, "connect_ms": None, "ttfb_ms": None, "total_ms": None,
        "error": None, "error_slug": None,
    }
    creds: tuple[str | None, str | None] = (None, None)
    if cfg.isolate_circuits:
        # Отдельная цепочка на каждую проверку (Tor IsolateSOCKSAuth):
        # зависший сервис не тянет за собой остальные.
        creds = (f"ow-{t.name}", secrets.token_hex(8))

    t0 = time.perf_counter()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            socks5_open(cfg.tor_socks, t.host, t.port, *creds), timeout=t.timeout
        )
        res["connect_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        deadline = t0 + t.timeout

        if t.mode == "tcp":
            res.update(ok=True, phase="done")
        else:
            res["phase"] = "request"
            if t.tls:
                await asyncio.wait_for(
                    writer.start_tls(_tls_context(), server_hostname=t.host),
                    timeout=max(1.0, deadline - time.perf_counter()),
                )
            req = (
                f"GET {t.path} HTTP/1.1\r\nHost: {t.host}\r\n"
                f"User-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            ).encode()
            writer.write(req)
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

            ok = res["status"] in t.expect_status
            if ok and t.expect_text:
                res["phase"] = "body"
                body = b""
                while len(body) < 256 * 1024:
                    chunk = await asyncio.wait_for(
                        reader.read(16384), timeout=max(1.0, deadline - time.perf_counter())
                    )
                    if not chunk:
                        break
                    body += chunk
                    if t.expect_text.encode() in body:
                        break
                if t.expect_text.encode() not in body:
                    ok = False
                    res["error_slug"] = "text_missing"
                    res["error"] = f"В ответе нет строки {t.expect_text!r}"
            if not ok and not res["error"]:
                res["error_slug"] = "bad_status"
                res["error"] = f"HTTP {res['status']}, ожидался {t.expect_status}"
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

    res["total_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return res


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
                    error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_checks_target_ts ON checks(target, ts DESC);

                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    url TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'http',
                    interval INTEGER,
                    timeout REAL,
                    expect_status TEXT NOT NULL DEFAULT '[200]',
                    expect_text TEXT,
                    note TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

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
            self.db.commit()

    # -- проверки ----------------------------------------------------------

    def add(self, r: dict[str, Any]) -> None:
        with self.lock:
            self.db.execute(
                "INSERT INTO checks (target, ts, ok, phase, status, connect_ms, ttfb_ms,"
                " total_ms, error_slug, error) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (r["target"], r["ts"], int(r["ok"]), r["phase"], r["status"], r["connect_ms"],
                 r["ttfb_ms"], r["total_ms"], r["error_slug"], r["error"]),
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
                "SELECT ts, ok, status, connect_ms, ttfb_ms, error_slug, error"
                " FROM checks WHERE target=? ORDER BY ts DESC LIMIT ?", (target, limit)
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def summary(self, target: str, window_s: float) -> dict[str, Any]:
        since = time.time() - window_s
        with self.lock:
            row = self.db.execute(
                "SELECT COUNT(*) n, SUM(ok) up, AVG(CASE WHEN ok THEN ttfb_ms END) ttfb,"
                " AVG(CASE WHEN ok THEN connect_ms END) conn"
                " FROM checks WHERE target=? AND ts>=?", (target, since)
            ).fetchone()
        n = row["n"] or 0
        up = row["up"] or 0
        return {
            "checks": n,
            "uptime": round(100.0 * up / n, 2) if n else None,
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
        out = []
        for r in rows:
            try:
                out.append(row_to_target(r, cfg))
            except ValueError as e:
                print(f"! цель {r['name']!r} пропущена: {e}", file=sys.stderr, flush=True)
        return out

    def add_target(self, row: dict[str, Any]) -> int:
        now = time.time()
        with self.lock:
            if self.db.execute("SELECT 1 FROM targets WHERE name=?", (row["name"],)).fetchone():
                raise Invalid(f"Цель с именем {row['name']!r} уже есть")
            cur = self.db.execute(
                "INSERT INTO targets (name, url, mode, interval, timeout, expect_status,"
                " expect_text, note, enabled, created_at, updated_at)"
                " VALUES (:name,:url,:mode,:interval,:timeout,:expect_status,"
                " :expect_text,:note,:enabled,:now,:now)", row | {"now": now})
            self.db.commit()
            self.targets_rev += 1
            return int(cur.lastrowid)

    def update_target(self, tid: int, row: dict[str, Any]) -> None:
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
                " timeout=:timeout, expect_status=:expect_status, expect_text=:expect_text,"
                " note=:note, enabled=:enabled, updated_at=:now WHERE id=:id",
                row | {"id": tid, "now": time.time()})
            if old["name"] != row["name"]:
                # История привязана к имени — переносим, иначе графики обнулятся.
                self.db.execute("UPDATE checks SET target=? WHERE target=?",
                                (row["name"], old["name"]))
            self.db.commit()
            self.targets_rev += 1

    def delete_target(self, tid: int) -> str:
        with self.lock:
            row = self.db.execute("SELECT name FROM targets WHERE id=?", (tid,)).fetchone()
            if not row:
                raise Invalid("Цель не найдена")
            self.db.execute("DELETE FROM targets WHERE id=?", (tid,))
            self.db.execute("DELETE FROM checks WHERE target=?", (row["name"],))
            self.db.commit()
            self.targets_rev += 1
            return row["name"]

    def seed_targets(self, cfg: Config) -> int:
        """Разовый импорт targets[] из конфига, пока таблица пуста."""
        with self.lock:
            if self.db.execute("SELECT 1 FROM targets LIMIT 1").fetchone():
                return 0
        added = 0
        for item in cfg.seed_targets:
            try:
                self.add_target(clean_target(item, cfg))
                added += 1
            except Invalid as e:
                print(f"! цель {item.get('name')!r} из конфига не импортирована: {e}",
                      file=sys.stderr, flush=True)
        return added

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
        for name, t in fresh.items():
            old = self.targets.get(name)
            if old is None or old.url != t.url or old.mode != t.mode:
                self.due[name] = now      # новая или переписанная цель — проверяем сразу
            elif name not in self.due:
                self.due[name] = now
        for name in list(self.due):
            if name not in fresh:
                self.due.pop(name, None)
                self.last.pop(name, None)
        self.targets = fresh

    # -- прогон ------------------------------------------------------------

    async def run_check(self, t: Target) -> dict[str, Any]:
        if t.name in self.running:
            return self.last.get(t.name, {})
        self.running.add(t.name)
        try:
            async with self.sem:
                res = await check_target(self.cfg, t)
        finally:
            self.running.discard(t.name)
        self.store.add(res)
        self.last[t.name] = res
        mark = "UP  " if res["ok"] else "DOWN"
        detail = f"{res['status']}" if res["status"] else (res["error_slug"] or "")
        print(f"[{time.strftime('%H:%M:%S')}] {mark} {t.name:<24} "
              f"{res['total_ms']:>7.0f} ms  {detail}", flush=True)
        return res

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
                "host": t.host,
                "label": t.label,
                "port": t.port,
                "mode": t.mode,
                "note": t.note,
                "interval": t.interval,
                "checking": t.name in self.running,
                "last": last,
                "day": self.store.summary(t.name, 86400),
                "week": self.store.summary(t.name, 7 * 86400),
                "history": self.store.history(t.name, 60),
            })
        up = sum(1 for x in out if x["last"] and x["last"].get("ok"))
        pending = sum(1 for x in out if not x["last"])
        return {
            "generated_at": time.time(),
            "started_at": self.started_at,
            "tor_ok": self.tor_alive(),
            "tor_socks": f"{self.cfg.tor_socks[0]}:{self.cfg.tor_socks[1]}",
            "up": up,
            "down": len(out) - up - pending,
            "pending": pending,
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

        def _send(self, code: int, body: bytes, ctype: str, cookie: str | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
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
                raise Invalid("Слишком большой запрос")
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

                if path.startswith("/api/targets/") and path.endswith("/history"):
                    if not self._public_ok():
                        return self._json(401, {"error": "Нужен вход"})
                    name = urllib.parse.unquote(path.split("/")[3])
                    return self._json(200, {"target": name,
                                            "history": store.history(name, 500)})

                if path == "/api/admin/targets":
                    if not self._require_admin():
                        return None
                    rows = [{
                        "id": t.id, "name": t.name, "url": t.url, "mode": t.mode,
                        "interval": t.interval, "timeout": t.timeout,
                        "expect_status": t.expect_status, "expect_text": t.expect_text,
                        "note": t.note, "enabled": t.enabled,
                    } for t in store.list_targets(cfg)]
                    return self._json(200, {"targets": rows,
                                            "defaults": {"interval": cfg.interval,
                                                         "timeout": cfg.timeout}})

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
                    row = clean_target(self._body(), cfg)
                    tid = store.add_target(row)
                    monitor.sync_targets()
                    return self._json(201, {"id": tid})

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
                    tid = self._target_id(path)
                    store.update_target(tid, clean_target(self._body(), cfg))
                    monitor.sync_targets()
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
                    name = store.delete_target(self._target_id(path))
                    monitor.sync_targets()
                    return self._json(200, {"deleted": name})
                return self._json(404, {"error": "Такого маршрута нет"})
            except Invalid as e:
                return self._json(400, {"error": str(e)})

        def _target_id(self, path: str) -> int:
            try:
                return int(path.rsplit("/", 1)[1])
            except (IndexError, ValueError) as e:
                raise Invalid("Не разобран идентификатор цели") from e

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
    down = [r for r in results if not r["ok"]]
    print(f"\nДоступно {len(results) - len(down)} из {len(results)}")
    for r in down:
        print(f"  ✗ {r['target']}: {r['error']}")
    return 1 if down else 0


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

    store = Store(cfg.db_path)

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

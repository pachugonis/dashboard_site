#!/usr/bin/env python3
"""
onionwatch — монитор доступности onion-сервисов (Tor hidden services).

Проверяет каждый адрес через SOCKS5-порт локального Tor, пишет историю
в SQLite и отдаёт веб-дашборд + JSON API.

Зависимости: только стандартная библиотека Python 3.11+ и запущенный tor.

    python3 onionwatch.py --config config.json          # демон + дашборд
    python3 onionwatch.py --config config.json --once   # один прогон в консоль
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
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
UA = "onionwatch/1.0"

# Коды ответа SOCKS5: стандартные (RFC 1928) + расширения Tor (prop304).
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


class ProxyDown(Exception):
    """SOCKS-порт Tor не принимает соединения."""


class SocksError(Exception):
    def __init__(self, code: int):
        self.code = code
        self.slug, self.message = SOCKS_ERRORS.get(code, ("socks_error", f"Код SOCKS 0x{code:02X}"))
        super().__init__(f"{self.message} (0x{code:02X})")


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
            raise ValueError(f"{self.name}: не удалось разобрать адрес {self.url!r}")

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
    targets: list[Target] = field(default_factory=list)


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

    if not cfg.db_path.startswith("/"):
        cfg.db_path = os.path.join(os.path.dirname(os.path.abspath(path)), cfg.db_path)

    seen: set[str] = set()
    for item in raw.get("targets", []):
        t = Target(
            name=item["name"],
            url=item["url"],
            interval=int(item.get("interval", cfg.interval)),
            timeout=float(item.get("timeout", cfg.timeout)),
            expect_status=list(item.get("expect_status", [200])),
            expect_text=item.get("expect_text"),
            mode=item.get("mode", "http"),
            note=item.get("note", ""),
        )
        if t.name in seen:
            raise ValueError(f"Дублирующееся имя цели: {t.name}")
        seen.add(t.name)
        cfg.targets.append(t)

    if not cfg.targets:
        raise ValueError("В конфиге нет ни одной цели (targets)")
    return cfg


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

        addr = host.encode("idna" if not host.isascii() else "ascii")
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
        with_suppress = getattr(writer, "wait_closed", None)
        if with_suppress:
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
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
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
                """
            )
            self.db.commit()

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

    async def _loop_target(self, t: Target) -> None:
        await asyncio.sleep(random.uniform(0, min(20.0, t.interval)))
        while True:
            try:
                await self.run_check(t)
            except Exception as e:  # проверка не должна ронять планировщик
                print(f"! ошибка планировщика для {t.name}: {e}", file=sys.stderr, flush=True)
            await asyncio.sleep(t.interval * random.uniform(0.9, 1.1))

    async def _loop_prune(self) -> None:
        while True:
            await asyncio.sleep(3600)
            removed = self.store.prune(self.cfg.retention_days)
            if removed:
                print(f"[db] удалено старых записей: {removed}", flush=True)

    async def serve(self) -> None:
        self.loop = asyncio.get_running_loop()
        tasks = [asyncio.create_task(self._loop_target(t)) for t in self.cfg.targets]
        tasks.append(asyncio.create_task(self._loop_prune()))
        await asyncio.gather(*tasks)

    def request_check(self, name: str) -> bool:
        """Вызывается из потока HTTP-сервера."""
        t = next((x for x in self.cfg.targets if x.name == name), None)
        if not t or self.loop is None:
            return False
        asyncio.run_coroutine_threadsafe(self.run_check(t), self.loop)
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
        out = []
        for t in self.cfg.targets:
            last = self.last.get(t.name)
            if last is None:
                rows = self.store.history(t.name, 1)
                last = rows[-1] if rows else None
            out.append({
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
        return {
            "generated_at": time.time(),
            "started_at": self.started_at,
            "tor_ok": self.tor_alive(),
            "tor_socks": f"{self.cfg.tor_socks[0]}:{self.cfg.tor_socks[1]}",
            "up": up,
            "total": len(out),
            "targets": out,
        }


# --------------------------------------------------------------------------
# HTTP-интерфейс
# --------------------------------------------------------------------------

def make_handler(monitor: Monitor):
    class Handler(BaseHTTPRequestHandler):
        server_version = UA
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # тихий лог
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: Any) -> None:
            self._send(code, json.dumps(payload, ensure_ascii=False).encode(),
                       "application/json; charset=utf-8")

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path in ("/", "/index.html"):
                try:
                    with open(os.path.join(HERE, "dashboard.html"), "rb") as fh:
                        self._send(200, fh.read(), "text/html; charset=utf-8")
                except FileNotFoundError:
                    self._send(404, b"dashboard.html not found next to onionwatch.py",
                               "text/plain; charset=utf-8")
            elif path == "/api/state":
                self._json(200, monitor.state())
            elif path.startswith("/api/targets/") and path.endswith("/history"):
                name = urllib.parse.unquote(path.split("/")[3])
                self._json(200, {"target": name, "history": monitor.store.history(name, 500)})
            else:
                self._json(404, {"error": "Такого маршрута нет"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            if path.startswith("/api/targets/") and path.endswith("/check"):
                name = urllib.parse.unquote(path.split("/")[3])
                if monitor.request_check(name):
                    self._json(202, {"queued": name})
                else:
                    self._json(404, {"error": f"Цель {name} не найдена"})
            else:
                self._json(404, {"error": "Такого маршрута нет"})

    return Handler


# --------------------------------------------------------------------------
# Точка входа
# --------------------------------------------------------------------------

async def run_once(cfg: Config, store: Store) -> int:
    monitor = Monitor(cfg, store)
    monitor.loop = asyncio.get_running_loop()
    results = await asyncio.gather(*(monitor.run_check(t) for t in cfg.targets))
    down = [r for r in results if not r["ok"]]
    print(f"\nДоступно {len(results) - len(down)} из {len(results)}")
    for r in down:
        print(f"  ✗ {r['target']}: {r['error']}")
    return 1 if down else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Монитор доступности onion-сервисов")
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--once", action="store_true", help="один прогон и выход (для cron/CI)")
    ap.add_argument("--no-web", action="store_true", help="только проверки, без дашборда")
    args = ap.parse_args()

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"Конфиг не прочитан: {e}", file=sys.stderr)
        return 2

    store = Store(cfg.db_path)

    if args.once:
        return asyncio.run(run_once(cfg, store))

    monitor = Monitor(cfg, store)
    if not monitor.tor_alive():
        print(f"Внимание: SOCKS-порт Tor {cfg.tor_socks[0]}:{cfg.tor_socks[1]} не отвечает. "
              f"Запустите tor или поправьте tor_socks в конфиге.", file=sys.stderr)

    if not args.no_web:
        httpd = ThreadingHTTPServer(cfg.listen, make_handler(monitor))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        print(f"Дашборд: http://{cfg.listen[0]}:{cfg.listen[1]}/  "
              f"(целей: {len(cfg.targets)}, база: {cfg.db_path})", flush=True)

    try:
        asyncio.run(monitor.serve())
    except KeyboardInterrupt:
        print("\nОстановлено.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

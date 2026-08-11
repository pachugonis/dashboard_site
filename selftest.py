"""Локальная проверка: поддельный SOCKS5-прокси + мини-HTTP-сервер.

Проверяет проверки, публичное API, админку (вход, CRUD целей, защиту
маршрутов) и валидацию адресов. Сеть Tor и настоящие onion-сервисы не нужны.
"""
import asyncio, http.cookiejar, json, os, sys, tempfile, threading, urllib.error, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onionwatch as ow

GOOD = "a" * 56 + ".onion"          # синтетические, но формально корректные v3-адреса
FAIL = "b" * 56 + ".onion"
LOGIN, PASSWORD = "admin", "correct-horse-battery"

fails: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}: {got!r}" + ("" if ok else f" ≠ {want!r}"))
    if not ok:
        fails.append(label)


# -- поддельная инфраструктура ---------------------------------------------

async def http_backend(reader, writer):
    try:
        await reader.readuntil(b"\r\n\r\n")
    except Exception:
        pass
    body = b"<html><title>hello onion</title></html>"
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                 % (len(body), body))
    try:
        await writer.drain()
    except Exception:
        pass
    writer.close()


def make_socks(backend_port):
    async def handle(reader, writer):
        try:
            n = (await reader.readexactly(2))[1]
            methods = await reader.readexactly(n)
            if 0x02 in methods:
                writer.write(b"\x05\x02"); await writer.drain()
                await reader.readexactly(1)
                ul = (await reader.readexactly(1))[0]; await reader.readexactly(ul)
                pl = (await reader.readexactly(1))[0]; await reader.readexactly(pl)
                writer.write(b"\x01\x00"); await writer.drain()
            else:
                writer.write(b"\x05\x00"); await writer.drain()
            await reader.readexactly(4)
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode()
            await reader.readexactly(2)
            if host == FAIL:
                writer.write(b"\x05\xf0\x00\x01" + b"\x00" * 6)
                await writer.drain(); writer.close(); return
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()
            br, bw = await asyncio.open_connection("127.0.0.1", backend_port)

            async def pipe(r, w):
                try:
                    while (chunk := await r.read(4096)):
                        w.write(chunk); await w.drain()
                except Exception:
                    pass
                finally:
                    w.close()
            await asyncio.gather(pipe(reader, bw), pipe(br, writer))
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()   # клиент отвалился раньше — это нормальный случай
    return handle


# -- HTTP-клиент с cookie ---------------------------------------------------

def _decode(payload: bytes):
    """Маршруты отдают и JSON, и HTML — тесту важен только код ответа."""
    try:
        return json.loads(payload or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"html_bytes": len(payload)}


class Client:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def __call__(self, method, path, body=None, admin_header=True):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if admin_header:
            req.add_header("X-Requested-With", "onionwatch")
        try:
            with self.opener.open(req) as r:
                return r.status, _decode(r.read())
        except urllib.error.HTTPError as e:
            return e.code, _decode(e.read())


# -- сценарий ---------------------------------------------------------------

async def main() -> int:
    backend = await asyncio.start_server(http_backend, "127.0.0.1", 0)
    socks = await asyncio.start_server(make_socks(backend.sockets[0].getsockname()[1]),
                                       "127.0.0.1", 0)
    sport = socks.sockets[0].getsockname()[1]

    tmp = tempfile.mkdtemp(prefix="onionwatch-selftest-")
    cfg = ow.Config(tor_socks=("127.0.0.1", sport), db_path=os.path.join(tmp, "t.db"),
                    timeout=10, interval=300)
    store = ow.Store(cfg.db_path)

    for spec in [
        {"name": "ok", "url": f"http://{GOOD}/", "expect_text": "hello onion", "timeout": 10},
        {"name": "wrong-text", "url": f"http://{GOOD}/", "expect_text": "нет такого", "timeout": 10},
        {"name": "wrong-status", "url": f"http://{GOOD}/", "expect_status": "404", "timeout": 10},
        {"name": "unreachable", "url": f"http://{FAIL}/", "timeout": 10},
        {"name": "tcp", "url": f"tcp://{GOOD}:1234", "mode": "tcp", "timeout": 10},
    ]:
        store.add_target(ow.clean_target(spec, cfg))

    mon = ow.Monitor(cfg, store)
    mon.loop = asyncio.get_running_loop()
    mon.sync_targets(force=True)
    print("\n1. Проверки целей")
    for t in list(mon.targets.values()):
        await mon.run_check(t)
        await mon.run_check(t)
    for name, want in {"ok": True, "wrong-text": False, "wrong-status": False,
                       "unreachable": False, "tcp": True}.items():
        check(f"{name} доступен", mon.last[name]["ok"], want)
    check("причина сбоя разобрана", mon.last["unreachable"]["error_slug"], "descriptor_not_found")

    httpd = ow.ThreadingHTTPServer(("127.0.0.1", 0), ow.make_handler(mon))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    api = Client(f"http://127.0.0.1:{httpd.server_address[1]}")

    print("\n2. Публичное API и дашборд")
    code, state = api("GET", "/api/state")
    check("/api/state отвечает", code, 200)
    check("сводка up/total", (state["up"], state["total"]), (2, 5))
    check("история пишется", len(state["targets"][0]["history"]), 2)
    check("страница дашборда отдаётся", api("GET", "/")[0], 200)

    print("\n3. Админка закрыта до входа")
    check("список целей без сессии", api("GET", "/api/admin/targets")[0], 401)
    check("создание цели без сессии", api("POST", "/api/admin/targets", {"url": "x"})[0], 401)
    check("админа ещё нет", api("GET", "/api/session")[1]["has_admin"], False)

    print("\n4. Вход по логину и паролю")
    store.set_admin(LOGIN, PASSWORD)
    check("пароль проверяется", store.check_password(LOGIN, PASSWORD), True)
    check("чужой пароль отвергнут", store.check_password(LOGIN, "wrong"), False)
    check("вход с неверным паролем", api("POST", "/api/login",
                                         {"login": LOGIN, "password": "wrong"})[0], 401)
    check("вход с верным паролем", api("POST", "/api/login",
                                       {"login": LOGIN, "password": PASSWORD})[0], 200)
    check("сессия видна", api("GET", "/api/session")[1]["login"], LOGIN)
    check("запрос без метки CSRF отклонён",
          api("GET", "/api/admin/targets", admin_header=False)[0], 403)
    check("список целей после входа", api("GET", "/api/admin/targets")[0], 200)

    print("\n5. Управление целями через админку")
    code, made = api("POST", "/api/admin/targets",
                     {"name": "новая", "url": f"http://{GOOD}/healthz",
                      "expect_status": "200, 301", "note": "заведена в админке"})
    check("цель создана", code, 201)
    tid = made.get("id")
    check("демон подхватил её без перезапуска",
          (mon.sync_targets(), "новая" in mon.targets)[1], True)
    check("дубль имени отклонён",
          api("POST", "/api/admin/targets", {"name": "новая", "url": f"http://{GOOD}/"})[0], 400)
    check("правка цели", api("PUT", f"/api/admin/targets/{tid}",
                             {"name": "новая-2", "url": f"http://{GOOD}/", "enabled": False})[0], 200)
    check("выключенная цель ушла из планировщика",
          (mon.sync_targets(), "новая-2" in mon.targets)[1], False)
    check("удаление цели", api("DELETE", f"/api/admin/targets/{tid}")[0], 200)
    check("после удаления её нет", len(api("GET", "/api/admin/targets")[1]["targets"]), 5)

    print("\n6. Валидация адресов")
    for label, url in [("кириллица в адресе", "http://ВАШ-АДРЕС-1.onion/"),
                       ("огрызок onion-адреса", "http://short.onion/"),
                       ("чужая схема", "ftp://" + GOOD + "/"),
                       ("tcp без порта", "tcp://" + GOOD + "/")]:
        code, resp = api("POST", "/api/admin/targets", {"name": label, "url": url})
        check(label + " отклонена", code, 400)

    print("\n7. Смена пароля и выход")
    check("смена с неверным текущим",
          api("POST", "/api/admin/password", {"current": "nope", "password": "x" * 12})[0], 403)
    check("короткий новый пароль",
          api("POST", "/api/admin/password", {"current": PASSWORD, "password": "abc"})[0], 400)
    check("выход", api("POST", "/api/logout")[0], 200)
    check("после выхода админка закрыта", api("GET", "/api/admin/targets")[0], 401)

    httpd.shutdown()
    print("\nПровалов:", len(fails) or "нет", *(f"\n  - {f}" for f in fails))
    return 1 if fails else 0

sys.exit(asyncio.run(main()))

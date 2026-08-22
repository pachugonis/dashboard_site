"""Локальная проверка: поддельный SOCKS5-прокси + мини-HTTP-сервер.

Проверяет проверки, зеркала целей, публичное API, админку (вход, CRUD целей,
защиту маршрутов) и валидацию адресов. Сеть Tor и настоящие onion-сервисы
не нужны.
"""
import asyncio, base64, http.cookiejar, json, os, re, sqlite3, struct, sys, tempfile, threading, time
import urllib.error, urllib.request, zlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onionwatch as ow

GOOD = "a" * 56 + ".onion"          # синтетические, но формально корректные v3-адреса
FAIL = "b" * 56 + ".onion"
CLEAR = "mirror.example"            # обычный адрес: такое же зеркало, но не onion
CLEAR_FAIL = "down.example"
DEAD = frozenset({FAIL, CLEAR_FAIL})
LOGIN, PASSWORD = "admin", "correct-horse-battery"

fails: list[str] = []
SEEN: list[bytes] = []              # заголовки запросов, дошедших до сервиса
AUTH: list[tuple[str, str]] = []    # SOCKS-авторизация: она же выбор цепочки


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}: {got!r}" + ("" if ok else f" ≠ {want!r}"))
    if not ok:
        fails.append(label)


# -- поддельная инфраструктура ---------------------------------------------

async def http_backend(reader, writer):
    head = b""
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except Exception:
        pass
    SEEN.append(head)
    parts = head.split(b" ")
    path = parts[1] if len(parts) > 1 else b"/"
    body, extra, code = b"<html><title>hello onion</title></html>", b"", b"200 OK"
    # На /gz отвечаем сжатым телом: раз проверки просят gzip, как браузер,
    # они обязаны его разжимать — иначе expect_text перестанет находиться.
    if path == b"/gz" and b"gzip" in head.lower():
        body, extra = zlib.compress(body, wbits=31), b"Content-Encoding: gzip\r\n"
    elif path == b"/captcha":
        # Так встречает капча анти-DDoS. Путь с заглавными буквами не случаен:
        # Location регистрозависим, и приводить его к нижнему регистру нельзя.
        code, extra = b"302 Found", b"Location: /Check?id=A1b2\r\n"
    elif path == b"/busy":
        code = b"503 Service Unavailable"
    writer.write(b"HTTP/1.1 " + code + b"\r\nContent-Length: %d\r\n%sConnection: close\r\n\r\n%s"
                 % (len(body), extra, body))
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
                ul = (await reader.readexactly(1))[0]; user = await reader.readexactly(ul)
                pl = (await reader.readexactly(1))[0]; password = await reader.readexactly(pl)
                AUTH.append((user.decode(), password.decode()))
                writer.write(b"\x01\x00"); await writer.drain()
            else:
                writer.write(b"\x05\x00"); await writer.drain()
            await reader.readexactly(4)
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode()
            await reader.readexactly(2)
            if host in DEAD:
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

def make_png(side: int = 2) -> bytes:
    """Настоящий PNG без сторонних библиотек — чтобы проверять разбор формата."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))
    rows = b"".join(b"\x00" + b"\xff\x00\x00" * side for _ in range(side))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", side, side, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows))
            + chunk(b"IEND", b""))


def make_svg(inner: str = '<circle cx="8" cy="8" r="8" fill="#f00"/>') -> bytes:
    """SVG с пространством имён — без него браузер покажет пустоту, и сервер это знает."""
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
            f'{inner}</svg>').encode()


def data_url(blob: bytes, ctype: str = "image/png") -> str:
    return f"data:{ctype};base64," + base64.b64encode(blob).decode()


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

    def raw(self, path, headers=None):
        """Ответ как есть: нужен для картинок и заголовков кэширования."""
        req = urllib.request.Request(self.base + path, method="GET")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()


# -- сценарий ---------------------------------------------------------------

async def main() -> int:
    backend = await asyncio.start_server(http_backend, "127.0.0.1", 0)
    socks = await asyncio.start_server(make_socks(backend.sockets[0].getsockname()[1]),
                                       "127.0.0.1", 0)
    sport = socks.sockets[0].getsockname()[1]

    tmp = tempfile.mkdtemp(prefix="onionwatch-selftest-")
    # retry_delay почти нулевой: сами ретраи проверить надо, ждать между ними — нет.
    cfg = ow.Config(tor_socks=("127.0.0.1", sport), db_path=os.path.join(tmp, "t.db"),
                    timeout=10, interval=300, retry_delay=0.01)
    store = ow.Store(cfg.db_path)

    for spec in [
        {"name": "ok", "url": f"http://{GOOD}/", "expect_text": "hello onion", "timeout": 10},
        {"name": "wrong-text", "url": f"http://{GOOD}/", "expect_text": "нет такого", "timeout": 10},
        {"name": "unreachable", "url": f"http://{FAIL}/", "timeout": 10},
        {"name": "tcp", "url": f"tcp://{GOOD}:1234", "mode": "tcp", "timeout": 10},
        {"name": "gzip", "url": f"http://{GOOD}/gz", "expect_text": "hello onion", "timeout": 10},
        {"name": "captcha", "url": f"http://{GOOD}/captcha", "expect_text": "hello onion",
         "timeout": 10},
        {"name": "busy", "url": f"http://{GOOD}/busy", "timeout": 10},
        # Зеркала: обычный адрес плюс onion, живые и мёртвые вперемешку.
        {"name": "зеркала", "clear": f"http://{CLEAR}/",
         "onions": [f"http://{GOOD}/", f"http://{FAIL}/"], "timeout": 10},
        {"name": "все-упали", "clear": f"http://{CLEAR_FAIL}/",
         "onions": [f"http://{FAIL}/"], "timeout": 10},
        {"name": "живо-зеркало", "clear": f"http://{CLEAR_FAIL}/",
         "onions": [f"http://{GOOD}/"], "timeout": 10},
    ]:
        store.add_target(*ow.clean_target(spec, cfg))

    mon = ow.Monitor(cfg, store)
    mon.loop = asyncio.get_running_loop()
    mon.sync_targets(force=True)
    print("\n1. Проверки целей")
    for t in list(mon.targets.values()):
        await mon.run_check(t)
        await mon.run_check(t)
    # Доступность — это «до сервиса достучались». Код ответа на неё не влияет:
    # и 503, и капча-редирект значат «работает, но придерживает».
    for name, want in {"ok": True, "wrong-text": False, "unreachable": False,
                       "tcp": True, "gzip": True, "captcha": True, "busy": True,
                       "зеркала": True, "все-упали": False, "живо-зеркало": True}.items():
        check(f"{name}: вердикт", mon.last[name]["ok"], want)
    check("причина сбоя разобрана", mon.last["unreachable"]["error_slug"], "descriptor_not_found")

    print("\n1a. Попытки, цепочки и заголовки")
    check("сбой цепочки не сразу даёт вердикт",
          mon.last["unreachable"]["attempts"], cfg.attempts)
    check("несовпадение текста повторять незачем", mon.last["wrong-text"]["attempts"], 1)
    check("успех достаётся с первой попытки", mon.last["ok"]["attempts"], 1)

    def circuits(prefix):
        return [password for user, password in AUTH if user.startswith(prefix)]

    alive = circuits("ow-ok#")
    check("живая цель ходит по одной цепочке", (len(alive), len(set(alive))), (2, 1))
    dead = circuits("ow-unreachable#")
    check("после сбоя цепочка берётся новая",
          (len(dead), len(set(dead))), (2 * cfg.attempts, 2 * cfg.attempts))
    mirrors = {user for user, _ in AUTH if user.startswith("ow-зеркала#")}
    check("у каждого зеркала своя цепочка", len(mirrors), 3)

    first = SEEN[0].decode("latin-1").lower()
    check("проверка представляется браузером", "firefox/" in first, True)
    check("шлётся Accept-Language", "accept-language:" in first, True)
    check("шлётся Accept-Encoding", "accept-encoding:" in first, True)
    check("наш служебный User-Agent наружу не уходит", "onionwatch/" in first, False)

    print("\n1б. Два состояния")
    for name, want in {"ok": "up", "tcp": "up", "gzip": "up", "captcha": "up",
                       "busy": "up", "зеркала": "up", "живо-зеркало": "up",
                       "wrong-text": "down", "unreachable": "down",
                       "все-упали": "down"}.items():
        check(f"{name}: состояние", mon.last[name]["state"], want)
    check("недоступность остаётся недоступностью",
          store.summary("unreachable", 3600)["uptime"], 0.0)

    # 503 и капча-редирект — это «работает, но придерживает нас». Причину
    # такого ответа никуда не пишем: на карточке её всё равно не показать.
    check("503 — это доступность", mon.last["busy"]["state"], "up")
    check("503 не роняет аптайм", store.summary("busy", 3600)["uptime"], 100.0)
    check("у доступного 503 нет описания сбоя", mon.last["busy"]["error"], None)
    check("капча-редирект — доступность", mon.last["captcha"]["state"], "up")
    check("под редиректом expect_text не проверяется", mon.last["captcha"]["phase"], "done")
    check("у редиректа тоже нет описания", mon.last["captcha"]["error"], None)
    # Заданная строка — единственное содержательное условие сверх ответа.
    check("нет искомой строки — недоступен", mon.last["wrong-text"]["error_slug"], "text_missing")

    print("\n1в. Зеркала")
    addrs = {a.url: a.id for a in mon.targets["зеркала"].addresses}
    states = store.addr_states()
    check("порядок адресов: обычный первым",
          [a.kind for a in mon.targets["зеркала"].addresses], ["clear", "onion", "onion"])
    check("живое зеркало доступно", states[addrs[f"http://{CLEAR}/"]]["state"], "up")
    check("мёртвое зеркало недоступно", states[addrs[f"http://{FAIL}/"]]["state"], "down")
    check("цель жива, пока отвечает хоть одно зеркало",
          (mon.last["зеркала"]["alive"], mon.last["зеркала"]["addrs"]), (2, 3))
    check("аптайм считается по цели, а не по каждому адресу",
          store.summary("зеркала", 3600)["uptime"], 100.0)
    # Тайминги в ленту берём у первого доступного адреса, поэтому упавший
    # главный не оставляет карточку без времени ответа.
    check("тайминги достались от живого зеркала",
          mon.last["живо-зеркало"]["url"], f"http://{GOOD}/")

    httpd = ow.ThreadingHTTPServer(("127.0.0.1", 0), ow.make_handler(mon))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    api = Client(f"http://127.0.0.1:{httpd.server_address[1]}")

    print("\n2. Публичное API и дашборд")
    code, state = api("GET", "/api/state")
    check("/api/state отвечает", code, 200)
    check("сводка по состояниям",
          (state["up"], state["down"], state["total"]), (7, 3, 10))
    check("история пишется", len(state["targets"][0]["history"]), 2)
    check("страница дашборда отдаётся", api("GET", "/")[0], 200)

    mirrors = next(t for t in state["targets"] if t["name"] == "зеркала")
    check("адреса отдаются наружу", len(mirrors["addresses"]), 3)
    check("у каждого адреса своё состояние",
          [a["last"]["state"] for a in mirrors["addresses"]], ["up", "up", "down"])
    check("вид адреса виден дашборду",
          [a["kind"] for a in mirrors["addresses"]], ["clear", "onion", "onion"])
    check("onion-адрес подписан коротко",
          mirrors["addresses"][1]["label"], "aaaaaaaa…aaaaaaaa.onion")

    print("\n3. Админка закрыта до входа")
    check("список целей без сессии", api("GET", "/api/admin/targets")[0], 401)
    check("создание цели без сессии", api("POST", "/api/admin/targets", {"url": "x"})[0], 401)
    check("публикация новости без сессии",
          api("POST", "/api/admin/news", {"text": "тайком"})[0], 401)
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
                     {"name": "новая", "clear": "https://mirror.test/",
                      "onions": [f"http://{GOOD}/healthz"], "note": "заведена в админке"})
    check("цель создана", code, 201)
    tid = made.get("id")
    check("демон подхватил её без перезапуска",
          (mon.sync_targets(), "новая" in mon.targets)[1], True)
    check("оба адреса сохранены",
          [a.url for a in mon.targets["новая"].addresses],
          ["https://mirror.test/", f"http://{GOOD}/healthz"])
    check("дубль имени отклонён",
          api("POST", "/api/admin/targets", {"name": "новая", "url": f"http://{GOOD}/"})[0], 400)

    # Идентификатор адреса переживает правку соседних полей: к нему привязано
    # последнее состояние, и терять его на каждом сохранении нельзя.
    was = [a.id for a in mon.targets["новая"].addresses]
    check("правка цели", api("PUT", f"/api/admin/targets/{tid}",
                             {"name": "новая", "clear": "https://mirror.test/",
                              "onions": [f"http://{GOOD}/healthz"], "note": "правка"})[0], 200)
    mon.sync_targets()
    check("уцелевшие адреса сохранили id",
          [a.id for a in mon.targets["новая"].addresses], was)
    check("убранный адрес исчез",
          api("PUT", f"/api/admin/targets/{tid}",
              {"name": "новая", "onions": [f"http://{GOOD}/healthz"]})[0], 200)
    mon.sync_targets()
    check("остался один адрес", len(mon.targets["новая"].addresses), 1)
    check("состояние убранного адреса удалено", was[0] in store.addr_states(), False)

    check("выключение цели", api("PUT", f"/api/admin/targets/{tid}",
                                 {"name": "новая-2", "url": f"http://{GOOD}/",
                                  "enabled": False})[0], 200)
    check("выключенная цель ушла из планировщика",
          (mon.sync_targets(), "новая-2" in mon.targets)[1], False)
    check("удаление цели", api("DELETE", f"/api/admin/targets/{tid}")[0], 200)
    check("после удаления её нет", len(api("GET", "/api/admin/targets")[1]["targets"]), 10)
    check("адреса удалённой цели тоже ушли",
          [aid for aid in was if aid in store.addr_states()], [])

    print("\n6. Валидация адресов")
    for label, url in [("кириллица в адресе", "http://ВАШ-АДРЕС-1.onion/"),
                       ("огрызок onion-адреса", "http://short.onion/"),
                       ("чужая схема", "ftp://" + GOOD + "/"),
                       ("tcp без порта", "tcp://" + GOOD + "/")]:
        code, resp = api("POST", "/api/admin/targets", {"name": label, "url": url})
        check(label + " отклонена", code, 400)

    for label, body in [
        ("цель без единого адреса", {"clear": "", "onions": []}),
        ("два обычных адреса", {"clear": "https://a.test/", "onions": ["https://b.test/"]}),
        ("одиннадцать onion-адресов",
         {"onions": [chr(c) * 56 + ".onion" for c in range(ord("a"), ord("a") + 11)]}),
        ("повтор адреса", {"onions": [f"http://{GOOD}/", f"http://{GOOD}/"]}),
    ]:
        code, resp = api("POST", "/api/admin/targets", {"name": label} | body)
        check(label + " отклонена", code, 400)

    print("\n7. Изображения целей")
    png = make_png()
    code, made = api("POST", "/api/admin/targets",
                     {"name": "с-картинкой", "url": f"http://{GOOD}/logo",
                      "image": data_url(png)})
    check("цель с картинкой создана", code, 201)
    img_id = made.get("id")
    status, headers, body = api.raw(f"/api/targets/{img_id}/image")
    check("картинка отдаётся", status, 200)
    check("тип содержимого", headers.get("Content-Type"), "image/png")
    check("байты совпадают с исходными", body == png, True)
    check("картинка кэшируется", "max-age" in (headers.get("Cache-Control") or ""), True)
    etag = headers.get("ETag")
    check("повторный запрос с ETag даёт 304",
          api.raw(f"/api/targets/{img_id}/image", {"If-None-Match": etag})[0], 304)
    check("признак картинки в публичном API",
          next(t["has_image"] for t in api("GET", "/api/state")[1]["targets"]
               if t["id"] == img_id), True)

    def image_version() -> int:
        return next(t["image_v"] for t in api("GET", "/api/state")[1]["targets"]
                    if t["id"] == img_id)

    api("PUT", f"/api/admin/targets/{img_id}",
        {"name": "с-картинкой", "url": f"http://{GOOD}/logo2"})
    check("правка цели без поля image картинку не трогает",
          api.raw(f"/api/targets/{img_id}/image")[0], 200)

    was = image_version()
    time.sleep(1.1)      # версия — это updated_at в секундах
    api("PUT", f"/api/admin/targets/{img_id}",
        {"name": "с-картинкой", "url": f"http://{GOOD}/logo2", "image": data_url(make_png(3))})
    check("версия картинки в URL растёт при замене", image_version() > was, True)
    check("отдаётся уже новая картинка",
          api.raw(f"/api/targets/{img_id}/image")[2] == make_png(3), True)

    svg = make_svg()
    code, svg_made = api("POST", "/api/admin/targets",
                         {"name": "с-вектором", "url": f"http://{GOOD}/logo.svg",
                          "image": data_url(svg, "image/svg+xml")})
    check("цель с SVG создана", code, 201)
    svg_id = svg_made.get("id")
    status, headers, body = api.raw(f"/api/targets/{svg_id}/image")
    check("SVG отдаётся как SVG", headers.get("Content-Type"), "image/svg+xml")
    check("SVG не перекодирован — байты те же", body == svg, True)
    # SVG исполняется браузером, а этот адрес открывается прямой ссылкой без
    # пароля: скрипты должна запрещать политика самого ответа.
    csp = headers.get("Content-Security-Policy") or ""
    check("у картинки своя глухая CSP", "default-src 'none'" in csp and "sandbox" in csp, True)
    check("общая политика страниц на картинку не распространяется",
          "script-src" in csp, False)
    api("DELETE", f"/api/admin/targets/{svg_id}")

    # Ссылка на кусок того же файла и вшитый растр — это рисование, а не выход
    # наружу: проверка форматов не должна отвергать нормальные логотипы.
    inner = ('<defs><linearGradient id="g"/></defs>'
             '<rect width="16" height="16" fill="url(#g)"/>'
             f'<image href="{data_url(png)}" width="8" height="8"/>')
    code, tame = api("POST", "/api/admin/targets",
                     {"name": "вектор-с-растром", "url": f"http://{GOOD}/mix.svg",
                      "image": data_url(make_svg(inner), "image/svg+xml")})
    check("SVG со ссылками внутрь себя принят", code, 201)
    api("DELETE", f"/api/admin/targets/{tame.get('id')}")

    for label, payload in [
        ("мусор вместо data-URL", "просто строка"),
        ("GIF больше не принимается", data_url(b"GIF89a\x01\x00", "image/gif")),
        ("WebP больше не принимается", data_url(b"RIFF\x00\x00\x00\x00WEBP", "image/webp")),
        ("чужая схема данных", "data:text/html;base64,PGh0bWw+"),
        ("тип не совпадает с содержимым", data_url(png, "image/jpeg")),
        ("PNG под видом SVG", data_url(png, "image/svg+xml")),
        ("пустое содержимое", "data:image/png;base64,"),
        ("SVG со скриптом",
         data_url(make_svg("<script>alert(1)</script>"), "image/svg+xml")),
        ("SVG с обработчиком события",
         data_url(make_svg('<circle r="8" onload="alert(1)"/>'), "image/svg+xml")),
        ("SVG со ссылкой наружу",
         data_url(make_svg('<image href="http://evil.onion/p.png"/>'), "image/svg+xml")),
        ("SVG с javascript-ссылкой",
         data_url(make_svg('<a href="javascript:alert(1)"><circle r="8"/></a>'),
                  "image/svg+xml")),
        ("SVG с DTD",
         data_url(b'<!DOCTYPE svg [<!ENTITY a "b">]>' + make_svg(), "image/svg+xml")),
        ("SVG без пространства имён",
         data_url(b'<svg viewBox="0 0 16 16"><circle r="8"/></svg>', "image/svg+xml")),
        ("оборванный SVG", data_url(make_svg()[:-6], "image/svg+xml")),
        ("слишком большая картинка",
         data_url(b"\x89PNG\r\n\x1a\n" + b"\x00" * 5_300_000)),
    ]:
        code, resp = api("POST", "/api/admin/targets",
                         {"name": label, "url": f"http://{GOOD}/", "image": payload})
        check(label + " отклонена", code, 400)

    # Предел — 5 МБ, и картинка на пару мегабайт обязана доезжать целиком:
    # в base64 это уже больше прежнего предела тела запроса.
    check("картинка на 2 МБ проходит",
          api("PUT", f"/api/admin/targets/{img_id}",
              {"name": "с-картинкой", "url": f"http://{GOOD}/",
               "image": data_url(b"\x89PNG\r\n\x1a\n" + b"\x00" * 2_000_000)})[0], 200)
    check("она же и отдаётся", len(api.raw(f"/api/targets/{img_id}/image")[2]), 2_000_008)

    check("удаление картинки",
          api("PUT", f"/api/admin/targets/{img_id}",
              {"name": "с-картинкой", "url": f"http://{GOOD}/", "image_clear": True})[0], 200)
    check("после удаления картинки нет", api.raw(f"/api/targets/{img_id}/image")[0], 404)
    check("удаление картинки не удалило цель",
          any(t["id"] == img_id for t in api("GET", "/api/admin/targets")[1]["targets"]), True)
    api("DELETE", f"/api/admin/targets/{img_id}")

    print("\n8. Новости")
    check("лента пуста, пока ничего не опубликовано", api("GET", "/api/news")[1]["news"], [])
    code, first = api("POST", "/api/admin/news",
                      {"text": "Первая новость\n\nи второй абзац к ней",
                       "image": data_url(png)})
    check("новость опубликована", code, 201)
    news_id = first.get("id")
    feed = api("GET", "/api/news")[1]["news"]
    check("новость видна в ленте", len(feed), 1)
    check("текст сохранён целиком", feed[0]["text"], "Первая новость\n\nи второй абзац к ней")
    check("признак картинки в ленте", feed[0]["has_image"], True)
    status, headers, body = api.raw(f"/api/news/{news_id}/image")
    check("картинка новости отдаётся", status, 200)
    check("тип содержимого картинки новости", headers.get("Content-Type"), "image/png")
    check("байты картинки новости совпадают", body == png, True)
    check("картинка новости кэшируется",
          "max-age" in (headers.get("Cache-Control") or ""), True)
    check("повторный запрос с ETag даёт 304",
          api.raw(f"/api/news/{news_id}/image", {"If-None-Match": headers.get("ETag")})[0], 304)

    # Картинка необязательна: новость без неё — это просто текст.
    code, plain = api("POST", "/api/admin/news", {"text": "Новость без картинки"})
    check("новость без картинки принята", code, 201)
    feed = api("GET", "/api/news")[1]["news"]
    check("свежая новость идёт первой", feed[0]["id"], plain.get("id"))
    check("у неё картинки нет", feed[0]["has_image"], False)
    check("картинки нет и по прямой ссылке",
          api.raw(f"/api/news/{plain.get('id')}/image")[0], 404)

    for label, body in [("новость без текста", {"text": "   "}),
                        ("новость без поля text", {}),
                        ("слишком длинный текст", {"text": "я" * 4001})]:
        check(label + " отклонена", api("POST", "/api/admin/news", body)[0], 400)

    # Картинку разбираем до вставки: иначе битый файл оставлял бы в ленте
    # опубликованную новость и ошибку в форме одновременно.
    check("новость с битой картинкой отклонена",
          api("POST", "/api/admin/news",
              {"text": "с мусором", "image": data_url(png, "image/jpeg")})[0], 400)
    check("отклонённая новость в ленту не попала",
          len(api("GET", "/api/news")[1]["news"]), 2)

    was_created = feed[1]["created_at"]
    was_version = feed[1]["image_v"]
    time.sleep(1.1)      # версия картинки — это updated_at в секундах
    check("правка новости", api("PUT", f"/api/admin/news/{news_id}",
                                {"text": "Первая новость, исправленная",
                                 "image": data_url(make_png(3))})[0], 200)
    edited = next(n for n in api("GET", "/api/news")[1]["news"] if n["id"] == news_id)
    check("текст заменён", edited["text"], "Первая новость, исправленная")
    check("версия картинки выросла", edited["image_v"] > was_version, True)
    check("отдаётся уже новая картинка",
          api.raw(f"/api/news/{news_id}/image")[2] == make_png(3), True)
    # Правка опечатки не должна поднимать новость обратно наверх ленты.
    check("дата публикации не сдвинулась", edited["created_at"], was_created)

    check("картинку новости можно убрать",
          api("PUT", f"/api/admin/news/{news_id}",
              {"text": "Первая новость, исправленная", "image_clear": True})[0], 200)
    check("после этого картинки нет", api.raw(f"/api/news/{news_id}/image")[0], 404)
    check("сама новость осталась",
          any(n["id"] == news_id for n in api("GET", "/api/news")[1]["news"]), True)

    check("удаление новости", api("DELETE", f"/api/admin/news/{news_id}")[0], 200)
    check("повторное удаление отклонено", api("DELETE", f"/api/admin/news/{news_id}")[0], 400)
    check("правка удалённой отклонена",
          api("PUT", f"/api/admin/news/{news_id}", {"text": "призрак"})[0], 400)
    check("в ленте осталась одна", len(api("GET", "/api/news")[1]["news"]), 1)
    check("страница новостей отдаётся", api("GET", "/news")[0], 200)

    print("\n9. Страницы и заголовок CSP")
    # Страницы и CSP правятся порознь, и рассогласование не видно ни в одном
    # серверном тесте: браузер просто молча не загружает ресурс. Схема blob:
    # в img-src не разрешена, поэтому createObjectURL для картинок непригоден.
    csp = api.raw("/admin")[1].get("Content-Security-Policy", "")
    check("CSP разрешает картинки из data:", "data:" in csp, True)
    here = os.path.dirname(os.path.abspath(__file__))
    pages = {}
    for page in ("admin.html", "dashboard.html", "news.html"):
        text = open(os.path.join(here, page), encoding="utf-8").read()
        pages[page] = "\n".join(line for line in text.splitlines()
                                if not line.lstrip().startswith("//"))   # без комментариев
        check(f"{page}: не грузит картинки по схеме, запрещённой CSP",
              "createObjectURL" not in pages[page] or "blob:" in csp, True)

    # Tor Browser отдаёт из canvas шум вместо нарисованного, и подмену видно
    # только глазами на карточке. Админка обязана проверять это перед обрезкой
    # и иметь запасной путь — иначе на сервер снова уедет рябь.
    admin_code = pages["admin.html"]
    check("админка проверяет, честно ли читается canvas",
          "canvasReadable()" in admin_code and "getImageData" in admin_code, True)
    check("у обрезки есть запасной путь без canvas",
          "passThroughRaster" in admin_code, True)
    check("карточка вписывает картинку целиком, а не режет",
          "object-fit: contain" in pages["dashboard.html"], True)
    check("картинку новости тоже не режет",
          "object-fit: contain" in pages["news.html"], True)

    # Ссылка на новости — в верхнем меню каждой страницы: заводится она руками
    # в трёх файлах, и забытая находится только глазами.
    for page, text in pages.items():
        check(f"{page}: в меню есть ссылка на новости",
              'href="/news"' in text and "Новости" in text, True)

    # Вкладки админки: цели и новости. Их переключение — целиком в браузере,
    # серверу о них знать нечего, поэтому проверяем разметку.
    check("в админке две вкладки",
          [m for m in re.findall(r'data-tab="(\w+)"', admin_code)], ["targets", "news"])
    for panel in ("tab-targets", "tab-news"):
        check(f"вкладке {panel} есть что показывать", f'id="{panel}"' in admin_code, True)

    # Предел картинки записан дважды: сервер режет байты, админка — длину
    # data-URL. Разъехавшись, они дают «файл слишком тяжёлый» на том, что сервер
    # бы принял, или наоборот — отказ уже после долгой загрузки.
    ceiling = ow.MAX_IMAGE * 4 / 3
    limit_chars = int(re.search(r"IMG_MAX_CHARS = (\d+)", admin_code).group(1))
    check("предел админки совпадает с серверным",
          0.99 * ceiling <= limit_chars <= ceiling, True)
    check("тело запроса вмещает предельную картинку в base64",
          ow.MAX_BODY > ceiling, True)

    print("\n10. Смена пароля и выход")
    check("смена с неверным текущим",
          api("POST", "/api/admin/password", {"current": "nope", "password": "x" * 12})[0], 403)
    check("короткий новый пароль",
          api("POST", "/api/admin/password", {"current": PASSWORD, "password": "abc"})[0], 400)
    check("выход", api("POST", "/api/logout")[0], 200)
    check("после выхода админка закрыта", api("GET", "/api/admin/targets")[0], 401)
    check("после выхода новости не публикуются",
          api("POST", "/api/admin/news", {"text": "тайком"})[0], 401)
    # Лента — публичная часть: её видно и без входа, пока не включён require_login.
    check("читать новости выход не мешает", api("GET", "/api/news")[0], 200)

    print("\n11. Миграция старых баз")
    # Без переноса старых записей аптайм за неделю считался бы по половине
    # колонки: у них state пуст, а SUM его пропускает.
    old_path = os.path.join(tmp, "old.db")
    old = sqlite3.connect(old_path)
    old.executescript("""
        CREATE TABLE checks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
          ts REAL NOT NULL, ok INTEGER NOT NULL, phase TEXT, status INTEGER,
          connect_ms REAL, ttfb_ms REAL, total_ms REAL, error_slug TEXT, error TEXT);
        INSERT INTO checks (target, ts, ok) VALUES ('старая', 1000000000, 1),
                                                   ('старая', 1000000001, 0);
    """)
    old.commit(); old.close()
    migrated = ow.Store(old_path)
    check("у старых записей появилось состояние",
          [r["state"] for r in migrated.history("старая")], ["up", "down"])
    check("аптайм по старой истории считается", migrated.summary("старая", 10 ** 12)["uptime"], 50.0)
    check("число попыток у старых записей неизвестно",
          migrated.history("старая")[0]["attempts"], None)

    # База времён трёх состояний и единственного адреса у цели. «С оговоркой»
    # значило «сервис на связи» и в аптайм шло как доступность — значит, и
    # переезжать оно должно в 'up', не меняя цифр.
    old_path = os.path.join(tmp, "old3.db")
    old = sqlite3.connect(old_path)
    old.executescript(f"""
        CREATE TABLE checks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
          ts REAL NOT NULL, ok INTEGER NOT NULL, phase TEXT, status INTEGER,
          connect_ms REAL, ttfb_ms REAL, total_ms REAL, error_slug TEXT, error TEXT,
          attempts INTEGER, state TEXT);
        INSERT INTO checks (target, ts, ok, state) VALUES ('старая', 1000000000, 1, 'up'),
                                                          ('старая', 1000000001, 0, 'warn');
        CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
          url TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'http', interval INTEGER, timeout REAL,
          expect_status TEXT NOT NULL DEFAULT '[200]', expect_text TEXT,
          note TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
          created_at REAL NOT NULL, updated_at REAL NOT NULL);
        INSERT INTO targets (name, url, created_at, updated_at)
          VALUES ('старая', 'http://{GOOD}/', 0, 0);
    """)
    old.commit(); old.close()
    migrated = ow.Store(old_path)
    check("оговорка переехала в доступность",
          [r["state"] for r in migrated.history("старая")], ["up", "up"])
    check("аптайм от переезда не изменился",
          migrated.summary("старая", 10 ** 12)["uptime"], 100.0)
    single = migrated.list_targets(cfg)
    check("единственный адрес цели переехал в таблицу адресов",
          [a.url for a in single[0].addresses], [f"http://{GOOD}/"])
    check("повторное открытие базы адрес не задваивает",
          [a.url for a in ow.Store(old_path).list_targets(cfg)[0].addresses],
          [f"http://{GOOD}/"])

    httpd.shutdown()
    print("\nПровалов:", len(fails) or "нет", *(f"\n  - {f}" for f in fails))
    return 1 if fails else 0

sys.exit(asyncio.run(main()))

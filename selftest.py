"""Локальная проверка: поддельный SOCKS5-прокси + мини-HTTP-сервер."""
import asyncio, json, os, sys, time, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onionwatch as ow

FAIL_HOST = "fail.onion"


async def http_backend(reader, writer):
    try:
        await reader.readuntil(b"\r\n\r\n")
    except Exception:
        pass
    body = b"<html><title>hello onion</title></html>"
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                 % (len(body), body))
    await writer.drain()
    writer.close()


def make_socks(backend_port):
    async def handle(reader, writer):
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
        head = await reader.readexactly(4)
        ln = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(ln)).decode()
        await reader.readexactly(2)
        if host == FAIL_HOST:
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
    return handle


async def main():
    backend = await asyncio.start_server(http_backend, "127.0.0.1", 0)
    bport = backend.sockets[0].getsockname()[1]
    socks = await asyncio.start_server(make_socks(bport), "127.0.0.1", 0)
    sport = socks.sockets[0].getsockname()[1]

    db = "/tmp/selftest.db"
    if os.path.exists(db):
        os.remove(db)
    cfg = ow.Config(tor_socks=("127.0.0.1", sport), db_path=db, timeout=10)
    cfg.targets = [
        ow.Target("ok", "http://good.onion/", expect_text="hello onion", timeout=10),
        ow.Target("wrong-text", "http://good.onion/", expect_text="нет такого", timeout=10),
        ow.Target("wrong-status", "http://good.onion/", expect_status=[404], timeout=10),
        ow.Target("unreachable", "http://" + FAIL_HOST + "/", timeout=10),
        ow.Target("tcp", "tcp://good.onion:1234", mode="tcp", timeout=10),
    ]
    store = ow.Store(db)
    mon = ow.Monitor(cfg, store)
    mon.loop = asyncio.get_running_loop()
    for t in cfg.targets:
        await mon.run_check(t)
        await mon.run_check(t)

    expect = {"ok": True, "wrong-text": False, "wrong-status": False,
              "unreachable": False, "tcp": True}
    bad = [n for n, e in expect.items() if mon.last[n]["ok"] != e]
    print("\nошибки ожиданий:", bad or "нет")
    print("текст сбоя unreachable:", mon.last["unreachable"]["error"])

    import threading
    httpd = ow.ThreadingHTTPServer(("127.0.0.1", 0), ow.make_handler(mon))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    state = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state"))
    print("api /api/state:", state["up"], "/", state["total"],
          "| история ok:", len(state["targets"][0]["history"]),
          "| uptime 24ч:", state["targets"][0]["day"]["uptime"])
    page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read()
    print("dashboard.html отдан:", len(page), "байт")
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/targets/ok/check", method="POST")
    print("ручная перепроверка:", urllib.request.urlopen(req).status)
    await asyncio.sleep(1.5)
    print("проверок в базе для ok:", len(store.history("ok", 100)))
    return 1 if bad else 0

sys.exit(asyncio.run(main()))

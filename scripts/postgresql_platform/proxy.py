"""Bounded TLS-byte passthrough; existing connections lose access on lease loss."""
import concurrent.futures
import selectors
import socket
import threading
import time

from .platform import proxy_route


def relay(client, config):
    # TLS is end to end between libpq and PostgreSQL. Server SANs must include
    # pg-{domain}-rw. This process never sees application credentials in clear.
    with client:
        route = proxy_route(config)
        identity = (route['primary_node'], route['authority'])
        with socket.create_connection((route['host'], route['port']), timeout=2) as upstream:
            client.settimeout(1)
            upstream.settimeout(1)
            with selectors.DefaultSelector() as poll:
                poll.register(client, selectors.EVENT_READ, upstream)
                poll.register(upstream, selectors.EVENT_READ, client)
                next_check = time.monotonic() + 1
                while True:
                    if time.time() >= route['expires_at']:
                        return
                    if time.monotonic() >= next_check:
                        route = proxy_route(config)
                        if (route['primary_node'], route['authority']) != identity:
                            return
                        next_check = time.monotonic() + 1
                    for key, _ in poll.select(timeout=0.2):
                        data = key.fileobj.recv(65536)
                        if not data:
                            return
                        key.data.sendall(data)


def serve(config):
    capacity = threading.BoundedSemaphore(64)
    def handle(client):
        try:
            relay(client, config)
        except (OSError, ValueError, KeyError):
            client.close()  # Fail closed; do not log user data/connection strings.
        finally:
            capacity.release()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((config.get('listen', '0.0.0.0'), 5432))
        listener.listen(64)
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            while True:
                client, _ = listener.accept()
                if capacity.acquire(blocking=False):
                    pool.submit(handle, client)
                else:
                    client.close()

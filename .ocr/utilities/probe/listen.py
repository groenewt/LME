import socket, time, sys
socks = []
for p in (5044, 8085):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", p)); s.listen(5)
    socks.append(s)
print("listening", flush=True)
time.sleep(20)

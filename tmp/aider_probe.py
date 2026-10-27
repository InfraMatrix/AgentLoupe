import socket

print(open("/etc/hostname").read().strip())
try:
    socket.create_connection(("127.0.0.1", 9), timeout=2)
except OSError as e:
    print("connect failed as expected:", e)

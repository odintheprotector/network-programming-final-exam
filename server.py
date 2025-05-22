#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Media-Chat – server (broadcast + private DM) with message logging
"""
import os, socket, threading, hashlib, pathlib

HOST, PORT  = '0.0.0.0', 5000
MEDIA_DIR   = pathlib.Path('received_media')
USER_DB     = pathlib.Path('user_credentials.txt')
LOG_FILE    = pathlib.Path('message_history.txt')
MAX_SIZE    = 10 * 1024 * 1024
ALLOWED_EXT = {'.jpg','.png','.gif','.mp3','.wav','.txt','.pdf'}

# ensure directories and files exist
MEDIA_DIR.mkdir(exist_ok=True)
USER_DB.touch()
LOG_FILE.touch()

clients_lock           = threading.Lock()
sock_by_user: dict[str, socket.socket] = {}
user_by_sock: dict[socket.socket, str] = {}

# ---------- utils ----------
def recv_line(sock):
    buf = b''
    while True:
        ch = sock.recv(1)
        if not ch or ch == b'\n':
            break
        buf += ch
    return buf.decode(errors='ignore')

def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

def log_message(line: str):
    """Append a line to the history log file."""
    with LOG_FILE.open('a', encoding='utf-8') as f:
        f.write(line + '\n')


def broadcast(line, exclude=None):
    """Send a line to all connected clients (except exclude)."""
    with clients_lock:
        dead = []
        for s in list(user_by_sock):
            if s is exclude:
                continue
            try:
                s.sendall((line + '\n').encode())
            except:
                dead.append(s)
        for d in dead:
            _remove_client(d)


def _remove_client(sock):
    if sock in user_by_sock:
        user = user_by_sock.pop(sock)
        sock_by_user.pop(user, None)
    try:
        sock.close()
    except:
        pass


def authenticate(conn):
    data = recv_line(conn).strip()
    if '|' not in data:
        conn.sendall(b"ERROR|Bad login\n")
        return None
    user, pwd = data.split('|', 1)
    h = hashlib.sha256(pwd.encode()).hexdigest()

    lines = USER_DB.read_text().splitlines()
    for ln in lines:
        ln = ln.strip()
        if not ln or '|' not in ln:
            continue
        u, hh = ln.split('|', 1)
        if u == user:
            if hh == h:
                conn.sendall(b"OK|Login successful\n")
                return user
            conn.sendall(b"ERROR|Wrong password\n")
            return None

    # new user
    USER_DB.write_text(USER_DB.read_text() + f"{user}|{h}\n")
    conn.sendall(b"OK|New user registered\n")
    return user

# ---------- client thread ----------
def handle(conn, addr):
    print('[+] connect', addr)
    user = authenticate(conn)
    if not user:
        conn.close()
        return

    with clients_lock:
        sock_by_user[user] = conn
        user_by_sock[conn] = user
    conn.sendall(f"INFO|Welcome {user}!\n".encode())

    try:
        while True:
            hdr = recv_line(conn)
            if not hdr:
                break
            parts = hdr.split('|')
            cmd = parts[0]

            # ---------- TEXT ----------
            if cmd == 'TEXT':
                msg = '|'.join(parts[1:])
                line = f"TEXT|{user}: {msg}"
                log_message(line)
                broadcast(line)

            # ---------- PRIVATE DM ----------
            elif cmd == 'DM':
                to = parts[1]
                msg = '|'.join(parts[2:])
                line = f"DM|{user}->{to}: {msg}"
                log_message(line)
                with clients_lock:
                    target = sock_by_user.get(to)
                if not target:
                    conn.sendall(f"ERROR|User {to} not online\n".encode())
                    continue
                # gửi cho chính người gửi + người nhận
                for s in {conn, target}:
                    try:
                        s.sendall((line + '\n').encode())
                    except:
                        _remove_client(s)

            # ---------- FILE upload ----------
            elif cmd == 'FILE':
                fname, sz, hrecv = parts[1], int(parts[2]), parts[3]
                ext = pathlib.Path(fname).suffix.lower()
                if sz > MAX_SIZE:
                    conn.sendall(b"ERROR|File too large\n")
                    continue
                if ext not in ALLOWED_EXT:
                    conn.sendall(b"ERROR|Bad type\n")
                    continue
                path = MEDIA_DIR / fname
                with open(path, 'wb') as f:
                    remain = sz
                    while remain:
                        chunk = conn.recv(min(4096, remain))
                        if not chunk:
                            raise ConnectionError
                        f.write(chunk)
                        remain -= len(chunk)
                if conn.recv(1) != b'\n':
                    raise ValueError("protocol")
                if sha(path) != hrecv:
                    conn.sendall(b"ERROR|Hash mismatch\n")
                    path.unlink()
                    continue
                conn.sendall(b"OK|File received\n")
                note = f"NOTIFY|{user} shared file: {fname}"
                log_message(note)
                broadcast(note)

            # ---------- GET_FILE ----------
            elif cmd == 'GET_FILE':
                fname = parts[1]
                path = MEDIA_DIR / fname
                if not path.is_file():
                    conn.sendall(b"ERROR|No file\n")
                    continue
                size = path.stat().st_size
                conn.sendall(f"FILE_TRANSFER|{fname}|{size}\n".encode())
                with open(path, 'rb') as f:
                    for ch in iter(lambda: f.read(4096), b''):
                        conn.sendall(ch)
                conn.sendall(b'\n')

    except Exception as e:
        print('[!] error', addr, e)
    finally:
        with clients_lock:
            _remove_client(conn)
        print('[-] disconnect', addr)

# ---------- main ----------
if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print('[*] listening', HOST, PORT)
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

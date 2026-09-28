import json
import os
import socket
import sqlite3
import threading

PORT = 5555
FORMAT = 'utf-8'
IP_ADDR = '0.0.0.0'
ADDR = (IP_ADDR, PORT)
DB_PATH = os.path.join(os.path.dirname(__file__), 'soc_dashboard.db')


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                severity TEXT,
                details TEXT,
                created_at TEXT,
                file_path TEXT,
                hash_value TEXT
            )
        """)
        conn.commit()


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
init_db()


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        while True:
            raw_bytes = conn.recv(2048)
            if not raw_bytes:
                break

            decoded_msg = raw_bytes.decode(FORMAT)
            data = json.loads(decoded_msg)
            print(f"[ALERT] {data['event_type']} detected on {data['file_path']}")

            with sqlite3.connect(DB_PATH) as connect:
                connect.execute(
                    """
                    INSERT INTO alerts(event_type, severity, details, created_at, file_path, hash_value)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data['event_type'],
                        data['severity'],
                        data['details'],
                        data['timestamp'],
                        data['file_path'],
                        data['hash'],
                    ),
                )
                connect.commit()
    except Exception as e:
        print(f"[error] {e}")
    finally:
        conn.close()


def start():
    server.listen()
    print(f'[Listening]..to [{PORT}]')
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()
            print(f"[Active connections] {threading.active_count() - 1}")
    except Exception as e:
        print(f"[error in connection...] [{e}]")


if __name__ == '__main__':
    start()

PORT = 5555
FORMAT = 'utf-8'
IP_ADDR = '0.0.0.0'
ADDR= (IP_ADDR,PORT)
import socket
import json
import threading
import psycopg
db_info = "dbname=soc_dashboard user=shivansh password=aftermeth host=localhost"

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(ADDR)
def handel_client(conn,addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        with psycopg.connect(db_info) as connect:
            with connect.cursor() as curr:
                while True:
                    raw_bytes = conn.recv(2048)
                    if(not raw_bytes):
                        break
                    decoded_msg = raw_bytes.decode(FORMAT)
                    data = json.loads(decoded_msg)
                    print(f"[ALERT] {data['event_type']} detected on {data['file_path']}")
                    curr.execute("""
                        INSERT INTO alerts(event_type, sevirity, details, created_at, file_path, hash_value) 
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """,(data['event_type'],data['severity'],data['details'],data['timestamp'],data['file_path'],data['hash']))
                    connect.commit()
    except Exception as e:
        print(f"[error] {e}")
    finally:
        conn.close()
        
def start():
    server.listen()
    print(f'[Listening]..to [{PORT}]')
    try:
        connected = True
        while connected:
            conn,addr = server.accept()
            thread = threading.Thread(target=handel_client,args=(conn,addr))
            thread.start()
            print(f"[Active connections] {threading.active_count()-1}")

    except Exception as e:
        print(f"[error in connection...] [{e}]")
start()
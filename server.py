PORT = 5555
FORMAT = 'utf-8'
IP_ADDR = '0.0.0.0'
ADDR= (IP_ADDR,PORT)
import socket
import json
import threading

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(ADDR)
def handel_client(conn,addr):
    pass
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
    
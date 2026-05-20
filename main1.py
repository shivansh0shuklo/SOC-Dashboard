import hashlib
# import datetime
import atexit as saviour
import socket as sock
import time 
import json as j
class FileGuard:
    ip = '127.0.0.1'
    port = 5555
    addr = (ip,port)
    def __init__(self,file_path):
        self.file_path = file_path##location  of the file assingned to watched
        self.baseline = self.calculate_hash()
        if(self.baseline):
            print(f"baseline establised for : {self.file_path}")
            print(f"current fingerprint {self.baseline}\n")
        self.client_socket = sock.socket(sock.AF_INET,sock.SOCK_STREAM)
        self.client_socket.connect(self.addr)
        saviour.register(self.client_socket.close)
    def calculate_hash(self):
        sha_256_hash = hashlib.sha256()
        try:
            with open(self.file_path,'rb') as f:
                for block_byte in iter(lambda: f.read(4096),b''):
                    sha_256_hash.update(block_byte)
                return sha_256_hash.hexdigest()
        except FileNotFoundError:
            print(f"[!] Error! file path - {self.file_path} not found!\n")
            return None

    def send_alert_to_server(self,event_type,re_calc,details,sevirity,file_path):
        pack = {
            "event_type":event_type,
            'severity':sevirity,
            'details':details,
            "timestamp":time.ctime(),
            'file_path':file_path,
            'hash':re_calc
        }
        try:
            s = j.dumps(pack).encode('utf-8')
            self.client_socket.send(s)
        except Exception as e:
            print(f"[ERROR!] {e}")         
    def monitor(self):
        print(f"[*] Monitoring {self.file_path}", end='\r')
        while True:
            try:
                time.sleep(3)
                re_calc = self.calculate_hash()
                if re_calc is None:
                    raise FileNotFoundError
                if re_calc != self.baseline:
                    print("[change is detected..]\n[logging it..]")
                    self.send_alert_to_server("MODIFICATION", re_calc, 'File Was Changed', 'CRITICAL', f"{self.file_path}")
                    self.baseline = re_calc
                else:
                    print("checking.....[Status: Secure] [ok]", end='\r')   
            except FileNotFoundError:
                print(f"\n[CRITICAL] Alert: {self.file_path} has been Deleted!")
                self.send_alert_to_server("DELETION", None, 'File is Removed!', 'CRITICAL', f'{self.file_path}')
                self.baseline = None
path_to_check = "abc.txt"
guard = FileGuard(path_to_check)
guard.monitor()
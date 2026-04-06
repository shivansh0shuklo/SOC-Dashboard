import hashlib
# import datetime
import atexit as saviour
# import socket as sock
import time 
# import os 
# import flask_socketio 
import psycopg 
# import numpy as np
db_info = "dbname=soc_dashboard user=shivansh password=aftermeth host=localhost"

class FileGuard:
    def __init__(self,file_path):
        self.file_path = file_path##location  of the file assingned to watched
        self.baseline = self.calculate_hash()
        self.conn =  psycopg.connect(db_info)
        saviour.register(self.conn.close)
        if(self.baseline):
            print(f"baseline establised for : {self.file_path}")
            print(f"current fingerprint {self.baseline}\n")
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
    def log_to_db(self,event_type,fingerprint,details,sevirity,file_path):
        sql = """INSERT INTO alerts(event_type,sevirety,details,file_path,hash_value)
                VALUES (%s,%s,%s,%s,%s)"""
        data = (event_type,sevirity,details,file_path,fingerprint)
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql,data)
                self.conn.commit()
        except Exception as e:
            print(f"[!] alert: error -[{e}]")

    def send_alert_to_server(self,data):
        pass
    def monitor(self):
        print(f"[*] Monitoring{self.file_path}",end='\r')
        while True:
            try:
                time.sleep(3)
                re_calc = self.calculate_hash()
                if(re_calc != self.baseline):
                    print("[change is detected..]\n[logging it..]")
                    self.log_to_db("MODIFICATION",re_calc,'File Was Changed','CRITICAL',f"{self.file_path}")
                    self.baseline = re_calc
                   
                else:
                    print("checking.....[Status: Secure] [ok]",end='\r')         
            except FileNotFoundError:
                print(f"\n[CRITICAL] Alert: {self.file_path} has been Deleted!")
                self.log_to_db("DELETION",None,'File is Removed!','ALERT',f'{self.file_path}')
            except PermissionError:
                print(f"\n[WARNING] Alert: Access is Denied! to {self.file_path}")
                self.log_to_db("PERMISSION_DENIED",None,'System Blocked Access!',"ALERT",f'{self.file_path}')
            except KeyboardInterrupt:
                print("[+]file guard shout down!")
                break
            except Exception as e:
                print(f'[EXCEPTION] Alert: error - {e}')
                self.log_to_db("SYSTEM-ERROR",None,f'{e}','EMERGENCY',f"{self.file_path}")

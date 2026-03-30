import hashlib
import time 
import os
class FileGuard:
    def __init__(self,file_path):
        self.file_path = file_path##location  of the file assingned to watched
        self.baseline = self.calculate_hash(file_path)
        if(self.baseline):
            print(f"baseline establised for : {self.file_path}")
            print(f"current fingerprint {self.baseline}\n")
    def calculate_hash(self):
        sha_256_hash = hashlib.sha256()
        try:
            with open(self.file_path,'rb') as f:
                for block_byte in iter(lambda: f.read(4096),b''):
                    sha_256_hash.update(block_byte)
                return sha_256_hash
        except FileNotFoundError:
            print(f"[!] Error! file path - {self.file_path} not found!\n")
            return None
    def monitor():
        try:
            pass

        except FileNotFoundError:
            pass
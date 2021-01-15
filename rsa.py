#! /usr/bin/env python3
'''
This script decrypt the encrypted content using a rsa private key
'''
import sys
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def rsaGenerate(filename='rsa'):
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
    public_key = private_key.public_key()
    private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(f'{filename}','wb') as f:
        f.write(private_key_bytes)
    with open(f'{filename}_pub.pem','wb') as f:
        f.write(public_key_bytes)

def rsaDecrypt(cipher,privatekey_bytes):
    private_key = serialization.load_pem_private_key(privatekey_bytes,backend=default_backend(),password=None)
    recovered = private_key.decrypt(cipher,padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()), algorithm = hashes.SHA256(),label = None))
    return recovered

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-g',help="Generate RSA key pair",action="store_true")
    parser.add_argument('file',help="Private key to decrypt or name of the RSA keys with -g")
    args = parser.parse_args()

    if args.g:
        if sys.argv[2]:
            rsaGenerate(sys.argv[2])
            
        else:
            rsaGenerate()
        sys.exit()

    print("Paste the encrypted content in hex format")
    try:
        cipher = bytes.fromhex(input(">> "))
    except:
        print('[Error] invalid format')
        sys.exit()
    with open(sys.argv[1],'rb') as f:
        key_bytes = f.read()

    recover = rsaDecrypt(cipher,key_bytes)
    print(f"Key used:\n{recover.hex()}")
    
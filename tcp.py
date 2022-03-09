from Crypto.Cipher import AES
import sys
import json
import binascii
from base64 import b64encode
from base64 import b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
import socket
plaintext='hello how are you?'
password='my password'


if (len(sys.argv)>1):
  plaintext=(sys.argv[1])
if (len(sys.argv)>2):
  password=(sys.argv[2])


salt = get_random_bytes(16)
key = PBKDF2('my password', salt, 32, count=1000000, hmac_hash_module=SHA256)
print(b64encode(salt))
print(b64encode(key))
def encrypt(plaintext,key, mode):
    
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext=cipher.encrypt(pad(plaintext, AES.block_size))
    # print("cipher",b64encode(salt+cipher.iv+ciphertext).decode('utf-8'))
    # print("iv",len(cipher.iv))
    # iv = b64encode(cipher.iv)
    # print(iv,b64encode(ciphertext))
    # ct = b64encode(ciphertext)
    
    print(len(salt),len(cipher.iv),len(ciphertext))
    print(len(salt+cipher.iv+ciphertext))
    print(len(b64encode(salt+cipher.iv+ciphertext).decode()))
    return b64encode(salt+cipher.iv+ciphertext)
# def decrypt(ciphertext,key, mode):
#   b64 = json.loads(ciphertext)
#   iv = b64decode(b64['iv'])
#   ct = b64decode(b64['ciphertext'])
#   cipher = AES.new(key, AES.MODE_CBC, iv)
#   pt = unpad(cipher.decrypt(ct), AES.block_size)
#   print('decrypted',pt)
  



# print("GCM Mode: Stream cipher and authenticated")
# print("\nMessage:\t",plaintext)
# print("Key:\t\t",password)


# ciphertext = encrypt('halt'.encode(),key,AES.MODE_CBC)

# print("Salt:\t\t",binascii.hexlify(salt))

class TCPClient():

    def sendTcpCommand(self, ip, port, message):
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, int(port)))
            sock.sendall(encrypt('halt'.encode(),key,AES.MODE_CBC))
            sock.setblocking(0)
            
                
            sock.close()
            return True
        except socket.error as ex:
            print(ex)
            return ex

tcp = TCPClient()
tcp_response = tcp.sendTcpCommand('172.17.0.231',2626,'halt')
print(encrypt('halt'.encode(),key,AES.MODE_CBC))
print(tcp_response)

#print()

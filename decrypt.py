import base64
import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.fernet import Fernet

def restore_File(data):  #Creates a data.txt file writing decrypted data
    with open("data.txt", "wb") as f:
        f.write(data)
    print("Your file has been decrypted.   data.txt")


file = input("Which file you wish to decrypt?")

#Checking if file exists
try:
    fi = open(file, "rb")
except:
    print("No such file")
    raise SystemExit
fi.close()

#Asking for the encryption password
password_provided = input("Enter encryption password")
password = password_provided.encode()

with open("salt.txt", "rb") as fi:
    salt = fi.read()

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

#Generating key
key = base64.urlsafe_b64encode(kdf.derive(password))

#Retrieving data - if exception then the password provided is wrong
with open(file, "rb") as fi:
    data = fi.read()
    try:
        f = Fernet(key)
        decrypted = f.decrypt(data)
    except:
        print("Invalid Password")
        raise SystemExit

    restore_File(decrypted) 

os.remove(file) #removed decrypted data
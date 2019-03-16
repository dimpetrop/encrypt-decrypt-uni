import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.fernet import Fernet

password_provided = input("Enter a strong password") #Asking user for encryption password
password = password_provided.encode() #Encoding it to byte

salt = os.urandom(16)   #Random Salt

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(password)) #Can only use kdf once

file = input("Which file you wish to encrypt?")

#Checking if file exists
try:
    with open(file, "rb") as fi:
        message = fi.read() 
except:
    print("No such file")
    raise SystemExit


os.remove(file) #Deleting file as contents are already retrieved on the message variable
print("File is being encrypted")
    

with open("encrypted.txt", "wb") as fi: #Creating file, encrypting using key, and writing as bytes
    f = Fernet(key)
    encrypted = f.encrypt(message)
    fi.write(encrypted)

with open("salt.txt", "wb") as fi: #Keeping salt to salt.txt. In current case, we do not care of how salt is stored but it must be the same for the decrypt script!
    fi.write(salt)


print("Your file is now encrypted.   encrypted.txt")




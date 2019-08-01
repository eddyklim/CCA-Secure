# Eduard Klimenko
# Uses aes-256-ctr and hmac-sha-256 to implement cca secure communication

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
import binascii
import hmac
import hashlib
import base64
import time

# Encryption and Decryption methods obtained from the web.
# AES supports multiple key sizes: 16 (AES128), 24 (AES192), or 32 (AES256).
key_bytes = 32

# Takes as input a 32-byte key and an arbitrary-length plaintext and returns a
# pair (iv, ciphtertext). "iv" stands for initialization vector.
def encrypt(key, plaintext):
    assert len(key) == key_bytes

    # Choose a random, 16-byte IV.
    iv = Random.new().read(AES.block_size)

    # Convert the IV to a Python integer.
    iv_int = int(binascii.hexlify(iv), 16) 

    # Create a new Counter object with IV = iv_int.
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Encrypt and return IV and ciphertext.
    ciphertext = aes.encrypt(plaintext)
    return (iv, ciphertext)

# Takes as input a 32-byte key, a 16-byte IV, and a ciphertext, and outputs the
# corresponding plaintext.
def decrypt(key, iv, ciphertext):
    assert len(key) == key_bytes

    # Initialize counter for decryption. iv should be the same as the output of
    # encrypt().
    iv_int = int(iv.encode('hex'), 16) 
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Decrypt and return the plaintext.
    plaintext = aes.decrypt(ciphertext)
    return plaintext

# Generates a new key for AES
key1 = Random.new().read(key_bytes)

# reads input file
fin=open("/home/seed/Desktop/hw2/kjv.txt","r")
fin_data=fin.read()
fin.close()

# measures time it takes to encrypt
start = time.time()
(iv, ciphertext) = encrypt(key1, fin_data)
end = time.time()
print("Encrypt time: ")
print(end - start)
print("\nEncryption Key:")
print(key1)
print("\nIV:")
print(iv)

# Generates a new key for HMAC
key2 = Random.new().read(key_bytes)
print("\nAuthentication Key:")
print(key2)

# calculates MAC(key2,message)
h = hmac.new( key2, ciphertext, hashlib.sha256 )
print("\nHash:")
print( h.hexdigest() )

# writes ENC(m), iv, HMAC(m) to a new file
fout = open("/home/seed/Desktop/hw2/kjv_enc.bin", "w")
fout.write(ciphertext)
fout.write(iv)
fout.write(h.hexdigest())
fout.close()

# writes generated keys to file
# encryption key followed by the authentication key
fout1 = open("/home/seed/Desktop/hw2/keys.bin", "w")
fout1.write(key1)
fout1.write(key2)
fout1.close()

# reads encrypted file that was just generated 
fin2=open("/home/seed/Desktop/hw2/kjv_enc.bin","rb")
fin2_data=fin2.read()
fin2.close()

# calculates the hash to check for authenticity
# ingore last 80 bytes
h2 = hmac.new( key2, (fin2_data[:-80]), hashlib.sha256 )
print("\nVerify Hash:")
print( h2.hexdigest() )

# print("\nDo they match?:")
# print h.hexdigest() == h2.hexdigest() # if true then it is authentic!

# grabs the appended IV and Hash and times decryption 
start2 = time.time()
plaintext = decrypt(key1, (fin2_data[-80:-64]), (fin2_data[:-80]))
end2 = time.time()
print("\nDecrypt time: ")
print(end2 - start2)

# writes decrypted text to new file
fout2 = open("/home/seed/Desktop/hw2/kjv_dec.txt", "w")
fout2.write(plaintext)
fout2.close()













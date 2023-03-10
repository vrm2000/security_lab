from Crypto.Cipher import AES
import os

# Genera una clave AES aleatoria de 256 bits
# Genera una clave AES aleatoria de 256 bits
master_key = os.urandom(32) # 32 bytes = 256 bits

# Muestra la clave generada
print("Clave generada:", master_key.hex())

# Define una función para cifrar datos con AES
def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return (ciphertext, cipher.nonce, tag)

# Define una función para descifrar datos con AES
def decrypt(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

# Genera una clave de prueba para cifrar
data_key = os.urandom(16) # 16 bytes = 128 bits

# Cifra la clave de prueba con la llave maestra
encrypted_data_key, nonce, tag = encrypt(data_key, master_key)

# Descifra la clave de prueba con la llave maestra
decrypted_data_key = decrypt(encrypted_data_key, master_key, nonce, tag)

# Compara la clave original y la clave descifrada
if decrypted_data_key == data_key:
    print("La clave maestra funciona correctamente")
else:
    print("La clave maestra no funciona correctamente")

# Append-adds at last
file1 = open(".env", "a")  # append mode
file1.write(f"\nMASTER_KEY={master_key.hex()}")
file1.close()

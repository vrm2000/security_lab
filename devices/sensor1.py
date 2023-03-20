from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time
import pickle
import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from argparse import ArgumentParser
import time, hmac, random, os, bson, pickle

with open(".env", "r") as file1:
    for line in file1:
        if "MASTER_KEY" in line:
            master_key = bytes.fromhex(line.split("=")[1].strip())
        else :
            master_key = os.urandom(32)
            file1 = open(".env", "a")  # append mode
            file1.write(f"\nMASTER_KEY={master_key.hex()}")
            file1.close()

class Sensor:
    def __init__(self, topic, output_function, args):
        # Credenciales de conexión
        load_dotenv()
        self.host = os.getenv("MQTT_BROKER_URL")
        self.port = 1883
        self.username = os.getenv("MQTT_USERNAME")
        self.password = os.getenv("MQTT_PASSWORD")
        # Temas MQTT
        self.topic = f"security/{topic}"
        self.output_function = output_function
        self.type_sensor = args.topic
        self.mac = self.rand_mac()
        self.client = self.connect()
        self.shared_key = master_key
        self.nonce = os.urandom(16)
 

    # Función de conexión con shiftr.io
    def on_connect(self, client, userdata, flags, rc):
        self.client.subscribe("platform")
        print("Conectado a shiftr.io con código de resultado: "+str(rc))

    def rand_mac(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )
    def generateNewMessage(self):
        message = str(self.output_function())
        if self.type_sensor in ["humidity", "temperature"]:
            message = message[0:4]
        return message
    


    def on_message(self, client, userdata, message):
        if message.topic == "platform":
            self.private_key, self.public_key, self.shared_key, self.other_public_key = self.diffie_hellman(client, message.payload)
            return
        self.shared_key = self.handle_server_public_key(message.payload)
        self.exchanged_keys = True

    def connect(self) -> mqtt.Client:
        # Conexión con shiftr.io
        client = mqtt.Client(client_id=f"{self.type_sensor}:{self.mac}")
        client.username_pw_set(self.username, self.password)
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.connect(self.host, self.port, 60)
        return client
    


    def ecb_encrypt(plaintext, key):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext


    def cbc_encrypt(plaintext, key):
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return (iv + ciphertext)

    def ctr_encrypt(plaintext, key):
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return (iv + ciphertext)
        
    def ofb_encrypt(plaintext, key):
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return (iv + ciphertext)

    def cfb_encrypt(plaintext, key):
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return (iv + ciphertext)

        
    def encrypt(self,plaintext,key):
        if self.topic == "movement" :
            ciphertext = cbc_encrypt(plaintext, key)
            print(ciphertext)
        elif self.topic == "temperature":
            ciphertext = ctr_encrypt(plaintext, key)
            print(ciphertext)
        elif self.topic == "humidity":
            ciphertext = ofb_encrypt(plaintext, key)
            print(ciphertext)
            
   #     else:
    #        ciphertext = ofb_encrypt(plaintext, key)
     #       self.client.publish(f"{self.topic}/{self.mac}", ciphertext)
        self.client.publish(f"{self.topic}/{self.mac}", ciphertext)


         
         
    def run(self,args):
        
        self.client.loop()
        time.sleep(1)
        print("Conection stablished with platform")
        # Ajustamos la longitud de la clave secreta para que cumpla los requisitos de longitud del algoritmo escogido
        
        key = self.shared_key
        self.type_sensor = args.topic
        self.topic = f"security/{self.type_sensor}"
        # Bucle principal
        while True:
            # Como additional data vamos a usar la MAC
            message = self.generateNewMessage()
            self.encrypt(message,key)
            # Esperar 5 segundos antes de la siguiente lectura
            time.sleep(args.publish_timeout)  

def main():
    parser = ArgumentParser()
    parser.add_argument("-t", "--topic", dest="topic",
        required=False, help="the topic where we send the data. This decide the type of sensor")
    
    parser.add_argument("-kt", "--key_timeout", dest="key_timeout", type=float,
        default=300, help="the time after which we need to regenerate the encryption keys in seconds")
    parser.add_argument("-pt", "--publish_timeout", dest="publish_timeout", type=float,
        default=5, help="the time after which the sensor will send new data in seconds")
    #  TODO: NOT IMPLEMENTED YET
    
    parser.add_argument("-ot", "--output_type", dest="output_type",
        choices=["float", "boolean"], default="float", help="define the sensor's output type")
    parser.add_argument("--min", dest="min", type=float,
        default=18, help="min output value")
    parser.add_argument("--max", dest="max", type=float,
        default=25, help="max output value")
    args = parser.parse_args()
    if args.output_type == "float":
        output_function = lambda : random.uniform(args.min, args.max)
    elif args.output_type == "boolean":
        output_function = lambda : random.choice([True, False])
    else:
        raise ValueError("output_type can not be this type")

    sensor = Sensor(topic=args.topic, output_function=output_function, args=args)
    sensor.run(args)

if __name__ == "__main__":
    main()

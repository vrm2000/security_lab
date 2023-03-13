import os
import time
import pickle
import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

client_public_key_topic = "key_exchange/client_public_key"
server_public_key_topic = "key_exchange/server_public_key"

class Sensor:
    def __init__(self, topic, output_function):
        # load .env file
        load_dotenv()
        # Credenciales de conexión
        self.host = os.getenv("MQTT_BROKER_URL")
        self.port = 1883
        self.username = os.getenv("MQTT_USERNAME")
        self.password = os.getenv("MQTT_PASSWORD")
        # Temas MQTT
        self.topic = f"security/{topic}"
        self.output_function = output_function
        self.client = self.connect()
        self.exchanged_keys = False
        self.shared_key = None
        self.private_key, self.public_key = self.dh_send_public_key_and_parameters()

    # Función de conexión con shiftr.io
    def on_connect(self, client, userdata, flags, rc):
        print("Conectado a shiftr.io con código de resultado: "+str(rc))
    
    def on_message(self, client, userdata, message):
        if self.exchanged_keys:
            # ignore if keys were already exchanged
            return
        if message.topic != server_public_key_topic:
            raise ValueError("Did not subscribe to this topic!")
        self.shared_key = self.handle_server_public_key(message.payload)
        self.exchanged_keys = True

    def connect(self) -> mqtt.Client:
        # Conexión con shiftr.io
        client = mqtt.Client()
        client.username_pw_set(self.username, self.password)
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.connect(self.host, self.port, 60)
        return client
    
    def dh_send_public_key_and_parameters(self):
        # subscribe to topic, where server will send his public key
        self.client.subscribe(server_public_key_topic)
        # Generate some parameters. These can be reused.
        parameters = dh.generate_parameters(generator=2, key_size=512)
        # Generate a private key for use in the exchange.
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        serialized_parameters = parameters.parameter_bytes(
            serialization.Encoding.PEM,
            serialization.ParameterFormat.PKCS3
        )
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pickled_data = pickle.dumps((serialized_parameters, serialized_public_key))
        # publish own public key to server
        self.client.publish(client_public_key_topic, pickled_data)
        return private_key, public_key

    def handle_server_public_key(self, serialized_server_public_key):
        # deserialize server public key
        server_public_key = serialization.load_pem_public_key(
            serialized_server_public_key
        )
        shared_key = self.private_key.exchange(server_public_key)
        return shared_key

    def run(self):
        # listen for key exchange messages
        while not self.shared_key:
            self.client.loop()
            time.sleep(1)

        print(f"Shared key is:\n{self.shared_key}")

        # Bucle principal
        while True:
            # Publicar los valores en los temas MQTT correspondientes
            payload = self.output_function()
            self.client.publish(self.topic, payload)
            print(f'Sending message on topic: {self.topic} with payload: {payload}')
            # Esperar 5 segundos antes de la siguiente lectura
            time.sleep(5)

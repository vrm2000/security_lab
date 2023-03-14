import os
import time
import random
import pickle
import paho.mqtt.client as mqtt
from argparse import ArgumentParser
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization


client_public_key_topic = "key_exchange/client_public_key"
server_public_key_topic = "key_exchange/server_public_key"

class Sensor:
    def __init__(self, topic, output_function, args):
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
        self.private_key, self.public_key = self.dh_send_public_key_and_parameters(args.key_generator, args.key_size)
    
    def connect(self) -> mqtt.Client:
        # Conexión con shiftr.io
        client = mqtt.Client()
        client.username_pw_set(self.username, self.password)
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.connect(self.host, self.port, 60)
        return client
    
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
    
    def dh_send_public_key_and_parameters(self, generator, key_size):
        # subscribe to topic, where server will send his public key
        self.client.subscribe(server_public_key_topic)
        # Generate some parameters. These can be reused.
        parameters = dh.generate_parameters(generator=generator, key_size=key_size)
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

    def run(self, args):
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
            time.sleep(args.publish_timeout)

def main():
    parser = ArgumentParser()
    parser.add_argument("-t", "--topic", dest="topic",
                        required=True, help="the topic where we send the data")
    # TODO: NOT IMPLEMENTED YET
    parser.add_argument("-kt", "--key_timeout", dest="key_timeout", type=float,
                        default=300, help="the time after which we need to regenerate the encryption keys in seconds")
    parser.add_argument("-pt", "--publish_timeout", dest="publish_timeout", type=float,
                        default=5, help="the time after which the sensor will send new data in seconds")
    # TODO: NOT IMPLEMENTED YET
    parser.add_argument("-kea", "--key_exchange_algorithm", dest="key_exchange_algorithm",
                        choices=["DH", "HADH", "ECDH"], default="DH", help="the used algorithm for key exchange")
    # TODO: NOT IMPLEMENTED YET
    parser.add_argument("-ea", "--encryption_algorithm", dest="encryption_algorithm",
                        choices=["AE", "AEAD"], default="AEAD", help="the algorithm for message encryption")
    parser.add_argument("-ot", "--output_type", dest="output_type",
                        choices=["float", "boolean"], default="float", help="define the sensor's output type")
    parser.add_argument("--min", dest="min", type=float,
                        default=18, help="min output value")
    parser.add_argument("--max", dest="max", type=float,
                        default=25, help="max output value")
    parser.add_argument("-g", "--key_generator", dest="key_generator", type=int, choices=[2, 5],
                        default=2, help="g value for diffie hellman key generation")
    parser.add_argument("-ks", "--key_size", dest="key_size", type=int, choices=[512, 1024, 2048],
                        default=512, help="key size for diffie hellman key generation")


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

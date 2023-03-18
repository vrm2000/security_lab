from dotenv import load_dotenv
import paho.mqtt.client as mqtt
from argparse import ArgumentParser
import time, hmac, random, os, bson, pickle
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes


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
        self.shared_key = None
        self.private_key, self.public_key = None, None
        self.other_public_key = None
        self.nonce = os.urandom(12)
        self.connection_stablished = False

    # Función de conexión con shiftr.io
    def on_connect(self, client, userdata, flags, rc):
        self.client.subscribe("platform/*")
        print("Conectado a shiftr.io con código de resultado: "+str(rc))

    def generate_dh_keys(self, parameters):
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return private_key, public_key, serialized_public_key
    
    def generate_ecdh_keys(self):
        # Generate an ephemeral private key for this exchange
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_key = ephemeral_private_key.public_key()
        serialized_ephemeral_public_key = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return ephemeral_private_key, ephemeral_public_key, serialized_ephemeral_public_key
    
    def diffie_hellman(self, client, payload, algorithm):
        # first receive the parameters and the other's public key
        print("Generating keys...")
        if algorithm == "hadh":
            serialized_parameters, serialized_other_public_key = pickle.loads(payload)
            # load parameters and other's public key
            parameters = serialization.load_pem_parameters(serialized_parameters)
            other_public_key = serialization.load_pem_public_key(
                serialized_other_public_key)
            # generate own key pair
            private_key, public_key, serialized_public_key = self.generate_dh_keys(parameters)
            # get shared secret
            shared_secret = private_key.exchange(other_public_key)
        elif algorithm == "ecdh":
            serialized_other_public_key = pickle.loads(payload)
            # Extract the received public key from the message
            other_public_key = serialization.load_pem_public_key(
                serialized_other_public_key)
            private_key, public_key, serialized_public_key = self.generate_ecdh_keys()
            # Compute the shared secret using the received public key and the ephemeral private key
            shared_secret = private_key.exchange(ec.ECDH(), other_public_key)
        else:
            raise ValueError(f"key encryption algorithm {algorithm} not supported.")
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'',
            backend=default_backend()
        )
        shared_key = hkdf.derive(shared_secret)

        # generate signature hmac to authenticate device
        signature = hmac.new(shared_key, (f"Soy un sensor con mac {self.mac}").encode("UTF-8"), digestmod="sha256").digest()

        # publish own public key to server and signature
        credentials = {"pubkey": serialized_public_key, "nonce": str(self.nonce.hex()), "signature": signature}
        client.publish(f'newDevice/{self.mac}', bson.dumps(credentials))
        print("Published own public key to platform")
        return private_key, public_key, shared_key, other_public_key

    def on_message(self, client, userdata, message):
        topic_split = message.topic.split('/')
        if len(topic_split) == 2 and topic_split[0] == "platform":
            algorithm = topic_split[1]
            self.private_key, self.public_key, self.shared_key, self.other_public_key = self.diffie_hellman(
                client,
                message.payload,
                algorithm
            )
            return

    def connect(self) -> mqtt.Client:
        # Conexión con shiftr.io
        client = mqtt.Client(client_id=f"{self.type_sensor}:{self.mac}")
        client.username_pw_set(self.username, self.password)
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.connect(self.host, self.port, 60)
        return client
    
    def rand_mac(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )
    def encrypt_publish_data(self, cipher, message, additional_data):
        ciphertext = cipher.encrypt(self.nonce, message.encode("utf-8"), additional_data)
        # Publicar los valores en los temas MQTT correspondientes
        print(f"({self.mac}) New {self.type_sensor} value: {message}")
        self.client.publish(f"{self.topic}/{self.mac}", ciphertext) 

    def generateNewMessage(self):
        message = str(self.output_function())
        if self.type_sensor in ["humidity", "temperature"]:
            message = message[0:4]
        return message

    def run(self,args):
        while self.shared_key == None:
            self.client.loop()
            time.sleep(1)
        print("Conection stablished with platform")
        # Ajustamos la longitud de la clave secreta para que cumpla los requisitos de longitud del algoritmo escogido
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'',
            backend=default_backend()
        )
        key = hkdf.derive(self.shared_key)
        cipher = AESGCM(key)
        self.type_sensor = args.topic
        self.topic = f"security/{self.type_sensor}"
        additional_data = hmac.new(key, self.shared_key, digestmod="sha256").digest()
        # Bucle principal
        while True:
            # Como additional data vamos a usar la MAC
            message = self.generateNewMessage()
            self.encrypt_publish_data(cipher, message, additional_data)
            # Esperar 5 segundos antes de la siguiente lectura
            time.sleep(args.publish_timeout)



def main():
    parser = ArgumentParser()
    parser.add_argument("-t", "--topic", dest="topic",
        required=True, help="the topic where we send the data. This decide the type of sensor")
    # TODO: NOT IMPLEMENTED YET
    parser.add_argument("-kt", "--key_timeout", dest="key_timeout", type=float,
        default=300, help="the time after which we need to regenerate the encryption keys in seconds")
    parser.add_argument("-pt", "--publish_timeout", dest="publish_timeout", type=float,
        default=5, help="the time after which the sensor will send new data in seconds")
    # TODO: NOT IMPLEMENTED YET
    parser.add_argument("-ea", "--encryption_algorithm", dest="encryption_algorithm",
        choices=["AE", "AEAD"], default="AEAD", help="the algorithm for message encryption")
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

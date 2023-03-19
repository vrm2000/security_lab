from dotenv import load_dotenv
import paho.mqtt.client as mqtt
from argparse import ArgumentParser
import time, hmac, random, os, bson
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
        self.nonce = os.urandom(12)
        self.stop_publish = False

        if hasattr(args, 'encryption_algorithm'):
            self.algorithm = f"ae/{args.encryption_algorithm.lower()}"
            if args.encryption_algorithm.lower() == "camellia" or args.encryption_algorithm.lower() == "chacha20":
                self.nonce = os.urandom(16)
        elif hasattr(args, 'encryption_algorithm_additionasl_data'):
            self.algorithm = f"aead/{args.encryption_algorithm_additional_data.lower()}"
        self.type_sensor = args.topic

        self.mac = self.rand_mac()
        self.client = self.connect()
        self.key = None
        self.private_key, self.public_key = None, None
        self.other_public_key = None
        self.connection_stablished = False

    # Función de conexión con shiftr.io
    def on_connect(self, client, userdata, flags, rc):
        self.client.subscribe("platform")
        if self.type_sensor == "humidity":
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
    
    def diffie_hellman(self, client, payload):
        # first receive the parameters and the other's public key
        if self.type_sensor == "humidity":
            print("Generating keys...")
        decoded_message = bson.loads(payload)
        # load algorithm and other's public key
        key_exchange_algorithm = decoded_message["key_exchange_algorithm"]
        serialized_other_public_key = decoded_message["serialized_public_key"]
        # Extract the received public key from the message
        other_public_key = serialization.load_pem_public_key(
                serialized_other_public_key)
        if key_exchange_algorithm == "HADH":
            serialized_parameters = decoded_message["serialized_parameters"]
            parameters = serialization.load_pem_parameters(serialized_parameters)
            # generate own key pair
            private_key, public_key, serialized_public_key = self.generate_dh_keys(parameters)
            # get shared secret
            shared_secret = private_key.exchange(other_public_key)
        elif key_exchange_algorithm == "ECDH":
            private_key, public_key, serialized_public_key = self.generate_ecdh_keys()
            # Compute the shared secret using the received public key and the ephemeral private key
            shared_secret = private_key.exchange(ec.ECDH(), other_public_key)
        else:
            raise ValueError(f"key exchange algorithm {key_exchange_algorithm} not supported.")
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'',
            backend=default_backend()
        )
        self.key = hkdf.derive(shared_secret)

        # generate signature hmac to authenticate device
        signature = hmac.new(self.key, (f"Soy un sensor con mac {self.mac}").encode("UTF-8"), digestmod="sha256").digest()

        # publish own public key to server and signature
        credentials = {
            "pubkey": serialized_public_key,
            "nonce": str(self.nonce.hex()),
            "signature": signature,
            "algorithm": self.algorithm.encode("utf-8")
        }
        client.publish(f'newDevice/{self.mac}', bson.dumps(credentials))
        if self.type_sensor == "humidity":
            print("Published own public key to platform")

        # Ajustamos la longitud de la clave secreta para que cumpla los requisitos de longitud del algoritmo escogido
        self.cipher = self.chooseEncryptionAlgorithm(self.key)

    def on_message(self, client, userdata, message):
        if message.topic == "platform":
            self.stop_publish = True
            self.diffie_hellman(
                client,
                message.payload
            )
            # Reanudamos comunicación una vez terminado el intercambio
            self.stop_publish = False
            return
        else:
            if self.type_sensor == "humidity":
                print(message.topic)

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
        encription = self.algorithm.split("/")
        encryptor = cipher.encryptor()
        if encription[0] == "aead":
            encryptor.authenticate_additional_data(additional_data)
        ciphertext = encryptor.update(message.encode("utf-8"))
        ciphertext += encryptor.finalize()
        if encription[1] == "aes":
            authentication_tag = encryptor.tag
            self.client.publish(f"{self.topic}/{self.mac}", ciphertext + authentication_tag)
        else:
            self.client.publish(f"{self.topic}/{self.mac}", ciphertext)

        # Publicar los valores en los temas MQTT correspondientes
        if self.type_sensor == "humidity":
            print(f"({self.mac}) New {self.type_sensor} value: {message}")
         
    def generateNewMessage(self):
        message = str(self.output_function())
        if self.type_sensor in ["humidity", "temperature"]:
            message = message[0:4]
        return message
    
    def chooseEncryptionAlgorithm(self, key):
        algo = self.algorithm.split("/")
        if algo[0] == 'ae':
            case = algo[1]
            if case == "aes":
                return Cipher(algorithm=algorithms.AES256(key), mode=modes.GCM(self.nonce), backend=default_backend())
            elif case == "camellia":
                return Cipher(algorithm=algorithms.Camellia(key), mode=modes.CTR(self.nonce), backend=default_backend())
            elif case == "chacha20":
                return Cipher(algorithm=algorithms.ChaCha20(key,self.nonce),mode=None, backend=default_backend())
            else:
                return 'Authenticated encyption algorithm not found!'
        elif algo[0] == 'aead':
            case = algo[1]
            if case == "aes":
                return Cipher(algorithm=algorithms.AES256(key), mode=modes.GCM(self.nonce), backend=default_backend())
            elif case == "chacha20":
                return Cipher(algorithm=algorithms.ChaCha20(key,self.nonce),mode=None,  backend=default_backend())
            else:
                return 'Authenticated encyption and additional data algorithm not found!'

    def run(self,args):
        while self.key == None:
            self.client.loop()
            time.sleep(1)
        if self.type_sensor == "humidity":
            print("Conection stablished with platform")
        self.topic = f"security/{self.type_sensor}"
        # Generamos los datos adicionales que será la MAC del dispositivo
        additional_data = hmac.new(self.key, self.mac.encode("utf-8"), digestmod="sha256").digest()
        # Bucle principal
        while self.stop_publish == False:
            self.client.loop()
            message = self.generateNewMessage()
            self.encrypt_publish_data(self.cipher, message, additional_data)
            # Esperar 5 segundos antes de la siguiente lectura
            time.sleep(args.publish_timeout)

def main():
    parser = ArgumentParser()
    parser.add_argument("-t", "--topic", dest="topic",
        required=True, help="the topic where we send the data. This decide the type of sensor")
    parser.add_argument("-pt", "--publish_timeout", dest="publish_timeout", type=float,
        default=5, help="the time after which the sensor will send new data in seconds")
    # TODO: NOT IMPLEMENTED YET
    parser.add_argument("-ae", "--encryption_algorithm", dest="encryption_algorithm",
        choices=["aes", "camellia", "chacha20"], default="aes", help="the algorithm for authenticated encryption of messages")
    parser.add_argument("-aead", "--encryption_algorithm_additional_data", dest="encryption_algorithm_additional_data",
        choices=["aes", "chacha20"], default="aes", help="the algorithm for authenticated encryption and additional data of messages")
    parser.add_argument("-ot", "--output_type", dest="output_type",
        choices=["float", "boolean"], default="float", help="define the sensor's output type")
    parser.add_argument("--min", dest="min", type=float,
        default=18, help="min output value", required=False)
    parser.add_argument("--max", dest="max", type=float,
        default=25, help="max output value", required=False)
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

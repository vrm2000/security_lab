import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from flask_socketio import SocketIO
from argparse import ArgumentParser
from datetime import datetime, timedelta
from flask import Flask, render_template
from cryptography.exceptions import InvalidTag
import os, bson, json, re, hmac, logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
import os, bson, hmac, pickle, logging, threading, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# parse arguments
parser = ArgumentParser()
parser.add_argument("-t", "--topics", dest="topics", nargs="+",
                    required=True, help="the topics that you want to subscribe to")
#  TODO: NOT IMPLEMENTED YET
parser.add_argument("-kea", "--key_exchange_algorithm", dest="key_exchange_algorithm",
    choices=["HADH", "ECDH"], default="HADH", help="the used algorithm for key exchange")
parser.add_argument("-kg", "--key_generator", dest="key_generator", type=int, choices=[2, 5],
                        default=2, help="g value for diffie hellman key generation")
parser.add_argument("-ks", "--key_size", dest="key_size", type=int, choices=[512, 1024, 2048],
                        default=512, help="key size for diffie hellman key generation")
args = parser.parse_args()

load_dotenv()

app = Flask(__name__)
app.config['SECRET'] = 'my secret key'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MQTT_KEEPALIVE'] = 5
app.config['MQTT_TLS_ENABLED'] = False

# Quitamos mensajes en la consola sobre GETs, POSTs y warnings
logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)
logging.getLogger('werkzeug').setLevel(logging.ERROR)
socketio = SocketIO(app)
# Diccionario con todos los dispositivos conectados y que han hecho intercambio Diffie-Hellman.
# Contiene clave compartida (shared_key) y el nonce de la comunicación (nonce)
devices = dict()
# Diccionario que contiene claves público (pubkey) y privada (privkey) de la plataforma.
platform_keys = dict()

def keyRotation():
    last_key_update = datetime.now()
    while True:
        update_time = datetime.now() - last_key_update
        if update_time > timedelta(seconds=30):
            last_key_update =  datetime.now()
            start_diffie_hellman()
        else:
            time.sleep(10)


@app.route('/')
def index():
    return render_template('index.html', devices=devices.keys())


def chooseEncryptionAlgorithm(algo, key, nonce):
        algo = algo.split("/")
        if algo[0] == 'ae':
            case = algo[1]
            if case == "aes":
                return Cipher(algorithm=algorithms.AES256(key), mode=modes.GCM(nonce), backend=default_backend())
            elif case == "camellia":
                return Cipher(algorithm=algorithms.Camellia(key), mode=modes.CTR(nonce), backend=default_backend())
            elif case == "chacha20":
                return Cipher(algorithm=algorithms.ChaCha20(key,nonce),mode=None, backend=default_backend())
            else:
                return 'Authenticated encyption algorithm not found!'
        elif algo[0] == 'aead':
            case = algo[1]
            if case == "aes":
                return Cipher(algorithm=algorithms.AES256(key), mode=modes.GCM(nonce), backend=default_backend())
            elif case == "chacha20":
                return Cipher(algorithm=algorithms.ChaCha20(key, nonce),mode=None, backend=default_backend())
            else:
                return 'Authenticated encyption and additional data algorithm not found!'


def register_device(message, client, mac):
    decoded_message = bson.loads(message)
    serialized_sensor_public_key = decoded_message["pubkey"]
    nonce = bytes.fromhex(decoded_message["nonce"])
    algo = decoded_message["algorithm"].decode("utf-8")

    shared_key = handle_sensor_public_key(serialized_sensor_public_key, mac)

    cipher = chooseEncryptionAlgorithm(algo, shared_key, nonce)
    algo = algo.split("/")
    devices[mac] =  {"shared_key": shared_key ,"nonce": nonce, "cipher": cipher, "encryption": algo}

    # generate signature hmac to compare with device's
    signature = hmac.new(shared_key, (f"Soy un sensor con mac {mac}").encode("UTF-8"), digestmod="sha256").digest()

    # check if device is who it claims to be
    try:
        if signature == decoded_message["signature"]:
            print(f"Sensor {mac} succesfully authenticated")
            print(f"Received new login from device {mac}")
            devices[mac]["authenticated"] = True
        else:
            print("Invalid HMAC Authentication")
            devices[mac]["authenticated"] = False
    except:
        print("An exception occurred tryng to authenticate...")


def handle_sensor_public_key(serialized_sensor_public_key, mac):
        # deserialize sensor public key
        sensor_public_key = serialization.load_pem_public_key(serialized_sensor_public_key)
        if args.key_exchange_algorithm == "HADH":
            shared_secret = platform_keys["privkey"].exchange(sensor_public_key)
        elif args.key_exchange_algorithm == "ECDH":
            shared_secret = platform_keys["privkey"].exchange(ec.ECDH(), sensor_public_key)
        else:
            raise ValueError("Key exchange algorithm not supported")
            
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'',
            backend=default_backend()
        )
        shared_key = hkdf.derive(shared_secret)
        return shared_key

def start_diffie_hellman():
    print("Generating keys...")

    if args.key_exchange_algorithm == "HADH":
        parameters = dh.generate_parameters(generator=args.key_generator, key_size=args.key_size)
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
        encoded_data = {"serialized_parameters" : serialized_parameters, "serialized_public_key" : serialized_public_key}
        encoded_data = bson.dumps(encoded_data)
    elif args.key_exchange_algorithm == "ECDH":
        # Generate an ephemeral private key for this exchange
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        encoded_data = {"serialized_parameters" : None, "serialized_public_key" : serialized_public_key}
        encoded_data = bson.dumps(encoded_data)
    else:
        raise ValueError(f"Key exchange algorithm '{args.key_exchange_algorithm}' not supported")
    
    platform_keys["pubkey"] = public_key
    platform_keys["privkey"] = private_key
        
    # publish own public key to server
    key_exchange_topic = f"platform/{args.key_exchange_algorithm.lower()}"
    
    client.publish(key_exchange_topic, encoded_data, retain=True)
    print(f"Public key published in topic {key_exchange_topic}")

def start_platform_configuration():
    print("Subscribing to main topics")
    for topic in args.topics:
            t = topic
            if topic.lower() == "all":
                t = "*"
            client.subscribe(f"security/{t}/*")
    client.subscribe("newDevice/*")
    start_diffie_hellman()


# On connect
def handle_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Running on http://127.0.0.1:5000")
        print('Connected successfully')
        start_platform_configuration()
    else:
        print('Bad connection. Code:', rc)

def decrypt_data(message, mac):
    key = devices[mac]["shared_key"]
    encription = devices[mac]["encryption"]
    cipher = devices[mac]["cipher"]
    algo = encription[1]
    encription = encription[0]
    decryptor = cipher.decryptor()
    # Se comprueba si hay additional data y se verifica
    if encription == "aead":
        #timestamp = message.payload[-35:-16].decode("utf-8")
        # Decrypt and verify the ciphertext and additional data
        additional_data = hmac.new(key,mac.encode("utf-8"), digestmod="sha256").digest()
        decryptor.authenticate_additional_data(additional_data)
    else:
        #timestamp = message.payload[-20:].decode("utf-8")
        fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(fecha)
    # timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    #if timestamp < last_key_update:
    #    return "NO"
    # Desencriptamos y obtenemos etiqueta de autenticación
    if algo == "aes":
        # Obtenemos etiqueta de autenticación del sensor
        tag = message.payload[-16:]
        # Desciframos y comprobamos etiqueta de autenticación
        plaintext = decryptor.update( message.payload[:-16]) + decryptor.finalize_with_tag(tag)
    else:
        plaintext = decryptor.update( message.payload)
        
    return plaintext.decode("utf-8")

def identify_sensor(message):
    if message == "humidity":
        submit = "newHumidityData"
    elif message == "temperature":
        submit = "newTemperatureData"
    elif message == "movement":
        submit = 'newMovementData'
    return submit

# On message
def handle_mqtt_message(client, userdata, message):
    topic = message.topic.split("/")
    if topic[0] == "newDevice":
        mac = topic[1]
        register_device(message.payload, client, mac)
        return

    # Identificamos el tipo de sensor y donde debe mandar los datos en la interfaz web
    submit = identify_sensor(topic[1])
    mac = topic[2]
    if devices[mac]["authenticated"] == True:
        plaintext = decrypt_data(message, mac)
        if plaintext != "NO":
            print(f'({mac}) Received new {submit[3:len(submit)-4].lower()} value: {plaintext}')
            data = dict(
                topic = message.topic,
                payload = plaintext
            )
            socketio.emit(submit, data=data)
    else:
        print(f"Sensor {mac} not authenticated...")

client = None

if __name__ == '__main__':
    host = os.getenv("MQTT_BROKER_URL")
    port = 1883
    username = os.getenv("MQTT_USERNAME")
    password = os.getenv("MQTT_PASSWORD")
    client = mqtt.Client(client_id="Platform")
    client.username_pw_set(username, password)
    client.on_connect = handle_connect
    client.connect(host, port, 60)
    client.on_message = handle_mqtt_message
    thread = threading.Thread(target=keyRotation)
    thread.daemon = True
    thread.start()
    client.loop_start()
    socketio.run(app, host='127.0.0.1', port=5000)

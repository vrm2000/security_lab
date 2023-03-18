import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from flask_socketio import SocketIO
from argparse import ArgumentParser
from flask import Flask, render_template
import os, bson,json, re, hmac, pickle, logging
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes

# parse arguments
parser = ArgumentParser()
parser.add_argument("-t", "--topics", dest="topics", nargs="+",
                    required=True, help="the topics that you want to subscribe to")
parser.add_argument("-g", "--key_generator", dest="key_generator", type=int, choices=[2, 5],
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

@app.route('/')
def index():
    return render_template('index.html', devices=devices.keys())

def register_device(message, client, mac):
    decoded_message = bson.loads(message)
    serialized_sensor_public_key = decoded_message["pubkey"]
    nonce = bytes.fromhex(decoded_message["nonce"])
    shared_key = handle_sensor_public_key(serialized_sensor_public_key, mac)
    devices[mac] =  {"shared_key": shared_key ,"nonce": nonce}
    hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'',
            backend=default_backend()
        )
    sharedKeyForSignature = hkdf.derive(shared_key)

    # generate signature hmac to compare with device's
    signature = hmac.new(sharedKeyForSignature, (f"Soy un sensor con mac {mac}").encode("UTF-8"), digestmod="sha256").digest()

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


def handle_sensor_public_key(serialized_server_public_key, mac):
        # deserialize server public key
        server_public_key = serialization.load_pem_public_key(serialized_server_public_key)
        shared_key = platform_keys["privkey"].exchange(server_public_key)
        return shared_key

def start_platform_configuration():
    print("Subscribing to main topics")
    for topic in args.topics:
            t = topic
            if topic.lower() == "all":
                t = "*"
            print(t, topic)
            client.subscribe(f"security/{t}/*")
    client.subscribe("newDevice/*")
    print("Generating keys...")
    parameters = dh.generate_parameters(generator=args.key_generator, key_size=args.key_size)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    platform_keys["pubkey"] = public_key
    platform_keys["privkey"] = private_key
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
    client.publish("platform",pickled_data, retain = True)
    print("Public key published in topic")

# On connect
def handle_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Running on http://127.0.0.1:5000")
        print('Connected successfully')
        start_platform_configuration()
    else:
        print('Bad connection. Code:', rc)

def decipher_data(message, mac):
    shared_key = devices[mac]["shared_key"]
    nonce = devices[mac]["nonce"]
    hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'',
            backend=default_backend()
        )
    key = hkdf.derive(shared_key)
    cipher = AESGCM(key)
    # Decrypt and verify the ciphertext and additional data
    additional_data = hmac.new(key,shared_key, digestmod="sha256").digest()
    plaintext = cipher.decrypt(nonce, message.payload, associated_data = additional_data).decode("utf-8")
    return plaintext

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
        if not(mac in devices.keys()):
            register_device(message.payload, client, mac)
        return

    # Identificamos el tipo de sensor y donde debe mandar los datos en la interfaz web
    submit = identify_sensor(topic[1])
    mac = topic[2]
    if devices[mac]["authenticated"] == True:
        plaintext = decipher_data(message, mac)

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
    client.loop_start()
    socketio.run(app, host='127.0.0.1', port=5000)

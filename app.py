import os
import pickle
from argparse import ArgumentParser
from flask import Flask, render_template
from flask_mqtt import Mqtt
from flask_socketio import SocketIO
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization

client_public_key_topic = "key_exchange/client_public_key"
server_public_key_topic = "key_exchange/server_public_key"

# parse arguments
parser = ArgumentParser()
parser.add_argument("-t", "--topics", dest="topics", nargs="+",
                    required=True, help="the topics that you want to subscribe to")
args = parser.parse_args()

load_dotenv()
app = Flask(__name__)
app.config['SECRET'] = 'my secret key'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MQTT_BROKER_URL'] = os.getenv("MQTT_BROKER_URL")
app.config['MQTT_BROKER_PORT'] = 1883
app.config['MQTT_USERNAME'] = os.getenv("MQTT_USERNAME")
app.config['MQTT_PASSWORD'] = os.getenv("MQTT_PASSWORD")
app.config['MQTT_KEEPALIVE'] = 5
app.config['MQTT_TLS_ENABLED'] = False

mqtt = Mqtt(app)
socketio = SocketIO(app)

peer_keys_dict = dict()


@app.route('/')
def index():
    return render_template('index.html')

@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    if rc == 0:
        print('Connected successfully')
        # subscribe to topics given by command line arguments
        for topic in args.topics:
            mqtt.subscribe(topic)
        # subscribe to topic for key exchange
        mqtt.subscribe(client_public_key_topic)
    else:
        print('Bad connection. Code:', rc)

def generate_keys(parameters):
    print("Generating keys...")
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Done generating keys")
    return private_key, public_key, serialized_public_key

def diffie_hellman(client, payload):
    # first receive the parameters and the other's public key
    serialized_parameters, serialized_other_public_key = pickle.loads(payload)
    # load parameters and other's public key
    parameters = serialization.load_pem_parameters(serialized_parameters)
    other_public_key = serialization.load_pem_public_key(
        serialized_other_public_key
    )
    # generate own key pair
    private_key, public_key, serialized_public_key = generate_keys(parameters)
    # get shared key
    shared_key = private_key.exchange(other_public_key)
    # publish own public key to server
    client.publish("key_exchange/server_public_key", serialized_public_key)
    print("Published own public key to server")
    return private_key, public_key, shared_key, other_public_key

@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    data = dict(
        topic=message.topic,
        payload=message.payload
    )
    # payload should not be decoded for key exchange
    if message.topic == client_public_key_topic:
        print("received a key")
        socketio.emit('newPublicKey', data=data)
        private_key, public_key, shared_key, other_public_key = diffie_hellman(client, message.payload)
        peer_keys_dict[other_public_key] = (private_key, public_key, shared_key)
        return

    # decode payload for plain text messages
    data['payload'] = data['payload'].decode()
    
    print('Received message on topic: {topic} with payload: {payload}'.format(**data))
    if message.topic == 'security/humidity':
        socketio.emit('newHumidityData', data=data)
    elif message.topic == 'security/temperature':
        socketio.emit('newTemperatureData', data=data)
    elif message.topic == 'security/movement':
        socketio.emit('newMovementData', data=data)


if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5000)

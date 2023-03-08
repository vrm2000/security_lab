from flask import Flask, render_template
from flask_mqtt import Mqtt
from flask_socketio import SocketIO
from dotenv import load_dotenv
import os

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

@app.route('/')
def index():
    return render_template('index.html')


@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    if rc == 0:
        print('Connected successfully')
        mqtt.subscribe("security/*")
    else:
        print('Bad connection. Code:', rc)


@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    data = dict(
        topic=message.topic,
        payload=message.payload.decode()
    )
    print('Received message on topic: {topic} with payload: {payload}'.format(**data))
    if message.topic == 'security/humidity':
        socketio.emit('newHumidityData', data=data)

    elif message.topic == 'security/temperature':
        socketio.emit('newTemperatureData', data=data)
    
    elif message.topic == 'security/movement':
        socketio.emit('newMovementData', data=data)

if __name__ == '__main__':
    socketio.run(host='127.0.0.1', port=5000)

from flask import Flask, render_template
#import threading
import paho.mqtt.client as mqtt

app = Flask(__name__,template_folder="templates")

broker = "myinstance-security.cloud.shiftr.io"
port = 1883
client = mqtt.Client()
username = "myinstance-security"
password = "SygyutF8JyLDfz5D"

#def print_messages(msg):
#    # do some background work here
#    print(msg)

# Create a separate thread to handle background task
#t = threading.Thread(target=print_messages)
#t.daemon = True
#t.start()

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("security/temperature")
    client.subscribe("security/humedity")
    client.subscribe("security/movement")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print("Topic " + msg.topic + " : ", msg.payload.decode())



# Ruta de la página principal de Flask
@app.route('/')
def index():
    return render_template('index.html')

# Conexión y suscripción a los temas MQTT cuando se inicia la aplicación
if __name__ == '__main__':
    # Configuración de MQTT
    client.username_pw_set(username=username, password=password)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker, port, 60)
    client.loop_forever()
    app.run()

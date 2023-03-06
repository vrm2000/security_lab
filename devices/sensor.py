import time
import paho.mqtt.client as mqtt

class Sensor:
    def __init__(self, topic, output_function):
        # Credenciales de conexión
        self.host = "myinstance-security.cloud.shiftr.io"
        self.port = 1883
        self.username = "myinstance-security"
        self.password = "SygyutF8JyLDfz5D"
        # Temas MQTT
        self.topic = f"security/{topic}"
        self.output_function = output_function
        self.client = self.connect()

    # Función de conexión con shiftr.io
    def on_connect(self, client, userdata, flags, rc):
        print("Conectado a shiftr.io con código de resultado: "+str(rc))

    def connect(self) -> mqtt.Client:
        # Conexión con shiftr.io
        client = mqtt.Client()
        client.username_pw_set(self.username, self.password)
        client.on_connect = self.on_connect
        client.connect(self.host, self.port, 60)
        return client

    def run(self):
        # Bucle principal
        while True:
            # Publicar los valores en los temas MQTT correspondientes
            self.client.publish(self.topic, self.output_function)
            # Esperar 5 segundos antes de la siguiente lectura
            time.sleep(5)

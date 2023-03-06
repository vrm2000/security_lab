from sensor import Sensor
import random

def main():
    temp_sensor = Sensor(topic="temperature", output_function=random.uniform(18, 25))
    temp_sensor.connect()
    temp_sensor.run()

if __name__ == "__main__":
    main()

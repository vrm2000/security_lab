from sensor import Sensor
import random

def main():
    humidity_sensor = Sensor(topic="humidity", output_function=lambda : random.uniform(30, 50))
    humidity_sensor.run()

if __name__ == "__main__":
    main()

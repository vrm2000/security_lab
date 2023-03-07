from sensor import Sensor
import random

def main():
    temperature_sensor = Sensor(topic="temperature", output_function=lambda : random.uniform(18, 25))
    temperature_sensor.run()

if __name__ == "__main__":
    main()

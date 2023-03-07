from sensor import Sensor
import random

def main():
    temp_sensor = Sensor(topic="humidity", output_function=lambda : random.uniform(30, 50))
    temp_sensor.run()

if __name__ == "__main__":
    main()
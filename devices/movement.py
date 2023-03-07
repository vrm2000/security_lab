from sensor import Sensor
import random

def main():
    temp_sensor = Sensor(topic="movement", output_function=lambda : random.choice([True, False]))
    temp_sensor.run()

if __name__ == "__main__":
    main()

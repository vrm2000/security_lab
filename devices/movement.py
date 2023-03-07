from sensor import Sensor
import random

def main():
    movement_sensor = Sensor(topic="movement", output_function=lambda : random.choice([True, False]))
    movement_sensor.run()

if __name__ == "__main__":
    main()

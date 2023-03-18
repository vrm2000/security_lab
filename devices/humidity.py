import subprocess
import sys

def main():
    subprocess.run([sys.executable, "devices/sensor.py", "-t", "humidity", "-ae", "camellia", "--min", "30", "--max", "50"])

if __name__ == "__main__":
    main()

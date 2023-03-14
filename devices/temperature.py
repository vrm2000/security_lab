import subprocess
import sys

def main():
    subprocess.run([sys.executable, "devices/sensor.py", "-t", "temperature", "--min", "18", "--max", "25"])

if __name__ == "__main__":
    main()

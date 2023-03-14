import subprocess
import sys

def main():
    subprocess.run([sys.executable, "devices/sensor.py", "-t", "movement", "-ot", "boolean"])

if __name__ == "__main__":
    main()

import subprocess
import sys

def main():
    subprocess.run([sys.executable, "devices/sensor.py", "-t", "movement", "-aead", "aes", "-ot", "boolean"])

if __name__ == "__main__":
    main()

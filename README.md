#### **Create the virtual environment**
`py -m venv env`

#### **Install libraries**
`pip install -r requirements.txt`

#### **Set environment variable**
`set FLASK_APP=app.py`

#### **Run project**
`flask run`

#### **Run server**
I do not know why but `flask run` is not working for me... That is why I am currently running the app like this:
`python app.py -t "humidity temperature"` in this case, the platform would only read two types of devices

It is possible to connect directly to all topics:
`python app.py -t "all"`
```
python app.py -t TOPICS [TOPICS ...]
The following arguments are required: -t/--topics
```

#### **Run sensor**
- `python devices/humidity.py`
- `python devices/movement.py`
- `python devices/temperature.py`

#### **Run custom sensor**
This can also just be changed in the python files for each sensor
```
python devices/sensor.py -t TOPIC [-kt KEY_TIMEOUT]
                 [-pt PUBLISH_TIMEOUT] [-kea {DH,HADH,ECDH}]
                 [-ea {AE,AEAD}] [-ot {float,boolean}] [--min MIN]     
                 [--max MAX] [-g {2,5}] [-ks {512,1024,2048}]
The following arguments are required: -t/--topic
```
- movement sensor: `python devices/sensor.py -t movement -ot boolean`
- temperature sensor: `python devices/sensor.py -t temperature --min 18 --max 25`
- humidity sensor: `python devices/sensor.py -t humidity --min 30 --max 50`

#### **Resources**
[MQTT in Flask](https://www.emqx.com/en/blog/how-to-use-mqtt-in-flask)
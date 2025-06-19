## 📡 Bi-Directional MQTT Messaging on a Single Device (Local Only)

This project enables **two-way communication** using the MQTT protocol on a **single computer**. Both publisher and subscriber run on the same machine, making it ideal for beginners to test MQTT locally using [Mosquitto](https://mosquitto.org/) and Python.

---

## 🛠 Requirements

* Python 3.7+
* Mosquitto MQTT Broker
* `paho-mqtt` Python library (version < 2.0)

---

## ⚙️ Setup Instructions

### ✅ Step 1: Install Mosquitto Broker

#### 🔹 On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install mosquitto mosquitto-clients
```

Note: Mosquitto runs on port 1883 by default. If it shows "Address already in use", it’s already running — no action needed.

### ✅ Step 2: Set Up Python Environment

```bash
# Create a project folder
mkdir mqtt-chat
cd mqtt-chat

# Create a Python virtual environment
python3 -m venv mqtt-env
source mqtt-env/bin/activate

# Install MQTT client (old version for compatibility)
pip install "paho-mqtt<2.0"
```

---

### ✅ Step 3: Add the Python Scripts

You’ll be running **two scripts simultaneously** on the same machine — each acting as a sender and receiver.

---

#### 🔧 `deviceA.py`

```python
import paho.mqtt.client as mqtt

def on_message(client, userdata, msg):
    print(f"Device A received: {msg.payload.decode()}")

client = mqtt.Client("DeviceA")
client.connect("localhost", 1883)
client.subscribe("deviceA/inbox")
client.on_message = on_message

client.loop_start()

while True:
    msg = input("Device A says: ")
    client.publish("deviceB/inbox", msg)
```

---

#### 🔧 `deviceB.py`

```python
import paho.mqtt.client as mqtt

def on_message(client, userdata, msg):
    print(f"Device B received: {msg.payload.decode()}")

client = mqtt.Client("DeviceB")
client.connect("localhost", 1883)
client.subscribe("deviceB/inbox")
client.on_message = on_message

client.loop_start()

while True:
    msg = input("Device B says: ")
    client.publish("deviceA/inbox", msg)
```

---

### ✅ Step 4: Run Mosquitto Broker (if not already running)

```bash
mosquitto
```

---

### ✅ Step 5: Run Both Scripts in Separate Terminals

Open two terminals **in the same folder** and **activate the virtual environment in both**:

#### 🔹 Terminal 1:

```bash
source mqtt-env/bin/activate
python3 deviceA.py
```

#### 🔹 Terminal 2:

```bash
source mqtt-env/bin/activate
python3 deviceB.py
```

---

## ✅ How It Works

* **deviceA** sends messages to `deviceB/inbox` and listens on `deviceA/inbox`.
* **deviceB** sends messages to `deviceA/inbox` and listens on `deviceB/inbox`.

This creates a **fully bidirectional communication channel** even on a single device.

---

## 💬 Example

**Terminal 1 (deviceA)**

```bash
Device A says: Hello from A
Device A received: Got your message, A!
```

**Terminal 2 (deviceB)**

```bash
Device B received: Hello from A
Device B says: Got your message, A!
```


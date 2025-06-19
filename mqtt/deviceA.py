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


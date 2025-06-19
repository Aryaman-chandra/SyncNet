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


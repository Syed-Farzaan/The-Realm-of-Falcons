#!/usr/bin/env python3

# This port scanner uses the Python nmap module.
# You'll need to install the following to get it work on Linux:
# Step 1: sudo apt install python3-pip
# Step 2: pip install python-nmap

import pyfiglet as pyfig 
from datetime import datetime
from queue import Queue
from time import sleep
import nmap
import ipaddress  	# To check if it is a valid ip-address.
import re  		    # To ensure that the input is correctly formatted.
import os
import threading
import socket


# Regular Expression Pattern to extract the number of ports you want to scan. 
# You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
port_min = 0
port_max = 65535
queue = Queue()
# A print_lock is what is used to prevent "double" modification of shared variables.
# This is used so while one thread is using a variable, others cannot access it.
# Once done, the thread releases the print_lock to be used it again.
print_lock = threading.Lock() 
nm = nmap.PortScanner()


# Initializing the color module class
class bcolors:
    PURPLE = '\033[1;95m'
    OKBLUE = '\033[1;94m'
    GREEN = '\033[1;92m'
    ORANGE = '\033[1;93m'
    RED = '\033[1;91m'
    CYAN = "\033[1;96m"
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'


def logo():
    print(bcolors.ORANGE, end='')
    logo_ascii = '''
                                              						.ze$$e.
								      .ed$$$eee..      .$$$$$$$P""
								   z$$$$$$$$$$$$$$$$$ee$$$$$$"
								.d$$$$$$$$$$$$$$$$$$$$$$$$$"
							      .$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$e..
							    .$$****""""***$$$$$$$$$$$$$$$$$$$$$$$$$$$be.
									     ""**$$$$$$$$$$$$$$$$$$$$$$$L
						The Guardians Of Justice       z$$$$$$$$$$$$$$$$$$$$$$$$$
				      	       Into The Spiral Dimensions    .$$$$$$$$P**$$$$$$$$$$$$$$$$
									    d$$$$$$$"              4$$$$$
									  z$$$$$$$$$                $$$P"
									 d$$$$$$$$$F                $P"
									 $$$$$$$$$$F
									  *$$$$$$$$"   Created by: Syed Bukhari, Sheikh Arsalan
									    "***""     Version-1.0.6

                                    				'''+bcolors.RESET+'''(A Multi-Tool Web Vulnerability Scanner)
                                 				   Catch us on Twitter: '''+bcolors.BG_LOW_TXT+'''@0xTheFalconX'''+bcolors.RESET+'''
    '''
    print(logo_ascii, end='')
    print(bcolors.RESET, end='')
  

def nmapScan(port):
    result = nm.scan(ip_add_entered, str(port))
    # The result is quite interesting to look at. Inspect the dictionary it returns. 
    # It contains what was sent to the command line in addition to the port status we're after. 
    # In nmap for port 80 and ip 10.0.0.2 you'd run: nmap -oX - -p 80 -sV 10.0.0.2
    #! print(result)

    # We extract the service information from the returned object
    service = (result['scan'][ip_add_entered]['tcp'][port]['name'])
    service_product = (result['scan'][ip_add_entered]['tcp'][port]['product'])
    service_version = (result['scan'][ip_add_entered]['tcp'][port]['version'])
    service_os = (result['scan'][ip_add_entered]['tcp'][port]['extrainfo'])
    print(f"{bcolors.GREEN}[*]{bcolors.RESET} Port {port}/tcp: {bcolors.GREEN}open{bcolors.RESET}" + f"\tService: {bcolors.GREEN}{service}{bcolors.RESET}" + f"\tVersion: {bcolors.GREEN}{service_product} {service_version}{bcolors.RESET}" + f"\tOS: {bcolors.GREEN}{service_os} {bcolors.RESET}")
    sleep(0.1)

def portScan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection = s.connect((ip_add_entered, port))
        with print_lock:
            nmapScan(port)
        connection.close()
    except:
        pass

# The threader thread pulls a worker from the queue and processes it
def threader():
    while True:
        # Gets a worker from the queue
        worker = queue.get()

        # Run the example job with any available worker in queue (thread)
        portScan(worker)

        # Completed with the job
        queue.task_done()

def perform_threading():
    # How many threads are we going to allow for
    for threads in range(60):
        thread = threading.Thread(target=threader)

        # Classifying as a daemon, so they will die when the main dies
        thread.daemon = True

        # Begins, must come after daemon definition
        thread.start()

def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


###################################################! Main Program Starts ###############################################
# Printing Title & LoGo
print(bcolors.CYAN, end='')
title= pyfig.figlet_format("The  Realm  of  Falcons", justify="center", font = "Doom", width=170)  
print(title, end='')  
print(bcolors.RESET, end='')
logo()

try:
    print(f"\n{bcolors.OKBLUE}Please wait.... checking for internet connectivity. {bcolors.RESET}")
    internet_availability = check_internet()
    if internet_availability == 0:
        print(f"\n{bcolors.RED}There seems to be some problem connecting to the internet. Please make sure you're connected to the internet. {bcolors.RESET}")
        raise SystemExit

    # Asking user to input the target they want to scan.
    while True:

        ip_add_entered = input("\nPlease enter the domain or ip address of the target that you want to scan: ")
        try:
            ip_address_obj = ipaddress.ip_address(ip_add_entered)
            # The following line will only execute if the ip address is valid.
            print(f"{bcolors.GREEN}You entered a valid ip address. {bcolors.RESET}")
            break

        except:
            print(f"{bcolors.RED}You entered an invalid ip address. {bcolors.RESET}")

    # Asking user to input port range they want to scan (0-65535).
    while True:

        print("Please enter the range of ports you want to scan (e.g: 60-120)")
        port_range = input("Enter port range: ")

        # Removing extra spaces so if we enter 80 - 90 instead of 80-90, the program will still work.
        port_range_valid = port_range_pattern.search(port_range.replace(" ",""))

        if port_range_valid:
            # We're extracting the low end of the port scanner range the user want to scan.
            port_min = int(port_range_valid.group(1))
            # We're extracting the upper end of the port scanner range the user want to scan.
            port_max = int(port_range_valid.group(2))
            break


    start_time = datetime.now()
    print(f"\nStarting Scan for {bcolors.ORANGE}{ip_add_entered}{bcolors.RESET} at {bcolors.ORANGE}{start_time}{bcolors.RESET}")
    perform_threading()

    # How many jobs to assign
    for worker in range(port_min, port_max + 1):   
        queue.put(worker)

    # wait until the thread terminates.
    queue.join()
    end_time = datetime.now()
    print(f"Ending Scan for {bcolors.ORANGE}{ip_add_entered}{bcolors.RESET} at {bcolors.ORANGE}{end_time}{bcolors.RESET}")
    total_time = end_time - start_time
    print(f"\nTotal Time Elasped: {bcolors.CYAN}{total_time}{bcolors.RESET}")


except KeyboardInterrupt:
    print(f"{bcolors.RED}\n[-] Received Ctrl+C hit, Shutting down...{bcolors.RESET}")
    raise SystemExit


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
import re  		    # To ensure that the input is correctly formatted.
import os           # To check for internet connectivity.
import threading
import socket
import requests


# Regular Expression Pattern to extract the number of ports you want to scan. 
# You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
queue = Queue()
# A print_lock is what is used to prevent "double" modification of shared variables.
# This is used so while one thread is using a variable, others cannot access it.
# Once done, the thread releases the print_lock to be used it again.
print_lock = threading.Lock() 
nm = nmap.PortScanner()
thread_list = [] 
subdomains = [] 


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

  
def nmapScan(port):
    result = nm.scan(target, str(port))
    # The result is quite interesting to look at. Inspect the dictionary it returns. 
    # It contains what was sent to the command line in addition to the port status we're after. 
    # In nmap for port 80 and ip 10.0.0.2 you'd run: nmap -oX - -p 80 -sV 10.0.0.2
    #! print(result)

    for host in nm.all_hosts():						# nm.all_hosts() = ['10.10.10.10']
        for proto in nm[host].all_protocols():      # nm[host].all_protocols() = tcp
            pass

    # We extract the service information from the returned object
    service = (result['scan'][host][proto][port]['name'])
    service_product = (result['scan'][host][proto][port]['product'])
    service_version = (result['scan'][host][proto][port]['version'])
    service_os = (result['scan'][host][proto][port]['extrainfo'])
    print(f"{bcolors.GREEN}[*]{bcolors.RESET} Port {port}/{proto}: {bcolors.GREEN}open{bcolors.RESET}" + f"\tService: {bcolors.GREEN}{service}{bcolors.RESET}" + f"\tVersion: {bcolors.GREEN}{service_product} {service_version}{bcolors.RESET}" + f"\tOS: {bcolors.GREEN}{service_os} {bcolors.RESET}")
    sleep(0.1)

def portScan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection = s.connect((target, port))
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

# This function sends a GET request to the specified URL and prints the response
def get_request(url):
  # Send the GET request to the specified URL
  response = requests.get(url)

  # Print the response code for the request
  print(f"Response for {url}: {response.status_code}")

# This function tries to discover directories and files in the web application
def discover():
  # Create a thread for each URL in the list
  threads = []
  for directory_or_file in DIRECTORIES_AND_FILES:
    # Create the full URL by combining the base URL and the directory or file
    url = BASE_URL + directory_or_file

    # Create a new thread for the URL and add it to the list of threads
    thread = threading.Thread(target=get_request, args=(url,))
    threads.append(thread)

    # Start the thread
    thread.start()

  # Wait for all threads to complete
  for thread in threads:
    thread.join()

def check_internet():
    os.system('ping -c1 google.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


###################################################! Main Program Starts ###############################################
if __name__ == '__main__':     #? To ensure that the program only runs when it's executed directly, rather than when it's imported as a module.

    from utilities.logo import logo
    from utilities.subdomain import scan
    from utilities.target_validation import validate_input

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

            target = input("\nPlease enter the domain or ip address of the target that you want to scan: ")

            validate_input(target)
            input_type = validate_input(target)

            if input_type == "IP":
                break
            elif input_type == "DOMAIN":
                break
            else:
                print(f"{bcolors.RED}You entered an invalid ip address/domain. {bcolors.RESET}")
              

        BASE_URL = f"http://{target}"
        # This is the list of common directories and files that we want to try
        DIRECTORIES_AND_FILES = ["/admin", "/login", "/index.html", "/about.html", "/contact.html", "/logout", "/.htpasswd", "/assets", "/news", "/downloads", "/robots.txt"]

        # Asking user to input port range they want to scan (0-65535).
        while True:

            print("Please enter the range of ports you want to scan (e.g: 60-120)")
            port_range = input("Enter port range: ")

            # Removing extra spaces so if we enter 80 - 90 instead of 80-90, the program will still work.
            port_range_fixer = port_range_pattern.search(port_range.replace(" ",""))

            if port_range_fixer:
                # We're extracting the low end of the port scanner range the user want to scan.
                port_min = int(port_range_fixer.group(1))
                # We're extracting the upper end of the port scanner range the user want to scan.
                port_max = int(port_range_fixer.group(2))

            if port_min >= 1 and port_max <= 65535:
                # The following line will only execute if the port range is valid.
                break
            else:
                print(f"{bcolors.RED}You entered an invalid port range. {bcolors.RESET}")


        start_time = datetime.now()
        print(f"\nStarting {bcolors.CYAN}Full Scan{bcolors.RESET} for {bcolors.ORANGE}{target}{bcolors.RESET} at {bcolors.ORANGE}{start_time}{bcolors.RESET}")
        perform_threading()

        # How many jobs to assign
        for worker in range(port_min, port_max + 1):   
            queue.put(worker)

        # wait until the thread terminates.
        queue.join()
        end_time = datetime.now()
        print(f"Ending {bcolors.CYAN}Full Scan{bcolors.RESET} for {bcolors.ORANGE}{target}{bcolors.RESET} at {bcolors.ORANGE}{end_time}{bcolors.RESET}")
        total_time = end_time - start_time
        print(f"\nTotal Time Elasped: {bcolors.CYAN}{total_time}{bcolors.RESET}")

        print(f"\nStarting {bcolors.CYAN}Directory/File bruteforcing{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
        discover()

        print(f"\nStarting {bcolors.CYAN}Subdomain enumeration{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
        with open("./wordlists/subdomains.lst", "r") as wordlist_file: 
            for line in wordlist_file: 
                word = line.strip()
                subdomain = word + "." + target
                t = threading.Thread(target=scan, args=(subdomain,))
                t.start()
                thread_list.append(t)
        for thread in thread_list:
            thread.join()

    except KeyboardInterrupt:
        print(f"{bcolors.RED}\n[-] Received Ctrl+C hit, Shutting down...{bcolors.RESET}")
        raise SystemExit

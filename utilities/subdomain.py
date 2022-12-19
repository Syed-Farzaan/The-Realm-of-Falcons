from falcon import subdomains
import socket

def scan(subdomain): 
	try:
		ip = socket.gethostbyname(subdomain) 
		subdomains.append(subdomain) 
		print("[+] Discovered subdomain:",subdomain)
	except: 
		pass

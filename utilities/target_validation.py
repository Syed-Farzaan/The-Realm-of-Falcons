import socket

def validate_ip(ip):
  try:
    socket.inet_aton(ip)
    return True
  except:
    return False

def validate_domain(domain):
  try:
    socket.gethostbyname(domain)
    return True
  except:
    return False

def validate_input(input):
  if validate_ip(input):
    return "IP"
  elif validate_domain(input):
    return "DOMAIN"
  else:
    return "INVALID"

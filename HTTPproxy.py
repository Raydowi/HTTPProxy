#
# Author: Ray Parker - u1054697
# Last Updated: 10 March 2023
#
# This is an HTTP Proxy application, which acts as a mediator between clients and servers. This program generally
# retrieves the GET requests from clients and prevents direct client-server communication in specified circumstances.
# Multithreading functionalities allows multiple client-server connections at the same time. It utilizes a blocklist,
# which prevents client-server communication from blocked hosts/ports. It also utilizes a local cache, which
# prevents unnecessary client-server communication if a local copy of the request is cached.
# 
# This is Ray Parker's PA1-Final assignment submission for CS 4480: Computer Network, Spring 2023 course. I verify 
# that the work in this assignment is my own. This code cannot be referenced/copied for other academic use. 

# Place your imports here
import signal
import socket
import threading
import sys
from optparse import OptionParser

# Global variables
cache = {} #Empty dictionary upon initialization
blocklist = [] #Empty list upon initialization
cacheIsEnabled = False #Cache is initially disabled
blocklistIsEnabled = False #Blocklist is initially disabled

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)

'''
# getHostNameandPort(getRequest): Given a full GET request, this method parses out the
# host name and (if specified) the port number.
# 
# PARAMS:
# getRequest - The unmodified GET request sent from the current client.
# 
# RETURN VALUES:
# hostUrl - The hostname from the GET request.
# port - If a port number is specified in the GET request, the value is returned here.
#        Otherwise, the default port value is set to 80.
'''
def getHostNameAndPort(getRequest):
    url = getRequest.split(" ")[1]
    hostURL = ""
    port = 80
    if url.startswith("http://"): #Special protocol for URLs that start with http
        url = url[7:len(url)]
        urlSplit = url.split('/', 1)
        # Check for port connection rq
        hasPort = urlSplit[0].find(':')
        if hasPort != -1:
            hostURL = urlSplit[0].split(':')[0]
            port = int(urlSplit[0].split(':')[1])
        else:
            hostURL = urlSplit[0]
    else: #The protocol for URLs that do not start with http
        urlSplit = url.split('/', 1)
        hostURL = urlSplit[0]
        hasPort = urlSplit[0].find(':')
        if hasPort != -1:
            hostURL = urlSplit[0].split(':')[0]
            port = int(urlSplit[0].split(':')[1])
    return hostURL, port

'''
# parseGetRequest(getRequest, conditional):  Given a full GET request, this method parses together
# a properly-formatted HTTP request that will be sent to the server. It assumes the GET request is
# valid with its formatting.
# 
# PARAMS:
# getRequest - The unmodified GET request sent from the current client.
# conditional - A boolean value specifying if a conditional GET request should be created (TRUE) or not (FALSE).
# 
# RETURN VALUE:
# httpRequest - A properly formatted HTTP request, which will be sent to the server.
'''
def parseGetRequest(getRequest, conditional):
    global cache #Ensure the global cache variable is updated
    
    splitLines = getRequest.split("\r\n")
    splitStr = splitLines[0].split(" ")
    url = splitStr[1]
    httpPart = splitStr[2]
    if url.startswith("http://"):
        url = url[7:len(url)]
    urlSplit = url.split('/', 1)
    host = urlSplit[0]
    filePath = "/" + urlSplit[1]
    httpRequest = splitStr[0] + " " + filePath + " " + httpPart + \
        "\r\n" + "Host:" + " " + host + "\r\n" + "Connection: close" + "\r\n"

    #If a conditional GET request is requested, add the approprate If-Modified-Since header
    #NOTE: This code runs under the assumption that the get request is in the cache
    if(conditional):
        savedData = cache[getRequest].decode()
        try:
            lastModified = (savedData.split("Date: ")[1]).split("\r\n")[0]
            httpRequest = httpRequest + "If-Modified-Since: " + lastModified + "\r\n"
        except:
            print("ERROR: Could not send Conditional GET Request.\n")

    i = 1
    while i < len(splitLines):
        # Skip any Connection headers
        if (splitLines[i].find("Connection") != -1) or (len(splitLines[i]) == 0):
            i += 1
            continue
        httpRequest += splitLines[i] + "\r\n"
        i += 1


    httpRequest += "\r\n"    
    return httpRequest

'''
# checkRequestValidity(getRequest):  Given a full GET request, this function checks that it has
# valid formatting. This is to ensure the client does not send a faulty request to the server.
# 
# PARAMS:
# getRequest - The unmodified GET request sent from the current client.
# 
# RETURN VALUE: 
# A string value that is either a Bad Request/Not Implemented, "GET", or "SPECIALREQ". A Bad Request/Not
# Implemented will be returned to the server; "GET" indicates it's a valid format for a GET request; and 
# "SPECIALREQ" indicates the request is one of the cache/blocklist control interface lines, which means 
# there is no outright client-server communication for this request.
'''
def checkRequestValidity(getRequest):
    # Must have an accurate number of spaces
    splitStr = getRequest.split(" ")
    if len(splitStr) < 3:
        return "HTTP/1.0 400 Bad Request\n"

    # Next, make sure it's a proper GET request
    method = splitStr[0]
    if method != 'GET':
        # check for other HTTP requests
        if method == 'POST' or method == 'PUT' or method == 'PATCH' or method == 'DELETE' or method == 'HEAD':
            return "HTTP/1.0 501 Not Implemented\n"
        else:
            return "HTTP/1.0 400 Bad Request\n"

    # Next, check URI format and make sure it's valid
    url = splitStr[1]
    if (len(url.split("://")) > 2):
        return "HTTP/1.0 400 Bad Request\n"
    if (len(url.split("://")) == 1) or (len(url.split("://")[1].split("/")) == 1):
        return "HTTP/1.0 400 Bad Request\n"

    # Next, make sure the right HTTP is used -- cannot be HTTP 1.1
    if not (splitStr[2].startswith("HTTP/1.0")):
        return "HTTP/1.0 400 Bad Request\n"

    splitLines = getRequest.split("\r\n")
    print("splitLines: ", splitLines)
    i = 1
    while i < len(splitLines):
        if (splitLines[i] == ""):
            i+=1
            continue
        if (not (": " in splitLines[i])) or (" :" in splitLines[i]):
            return "HTTP/1.0 400 Bad Request\n"
        print(splitLines[i].split(" ")[0])
        i+=1
    
    #Finally, check if any of the special absolute paths for cache/blocklist control are used
    path = url.split("://")[1].split("/", 1)[1]
    path = "/" + path
    if cacheBlocklistControl(path):
        return "SPECIALREQ"
    
    # Everything looks good! Return a non-bad request
    return "GET"

'''
# cacheProtocol(getRequest):  Given a full GET request, this function runs the specified cache
# protocol. It parses a conditional HTTP request and sends it to the server. If it responds with a Not
# Modified header, then a locally-cached version is sent to the client; otherwise, the modified version 
# is fetched from the server and sent to the client. This method only runs when we know the cache is
# enabled and the GET request is used as a key in the cache.
# 
# PARAMS:
# getRequest - The unmodified GET request sent from the current client. This GET request is always in the
# global cache dictionary when this function is called, and this GET request is used as a key to access
# the locally-cached value for that request.
# 
# RETURN VALUE: 
# [None]
'''
def cacheProtocol(getRequest):
    
    global cache #Ensure the global cache variable is updated
    
    # Parse GET request into HTTPRequest
    hostName, serverPort = getHostNameAndPort(getRequest)
    conditionalHttpRequest = parseGetRequest(getRequest, True)
    
    # Initialize the proxy-client (speaking) socket, it will speak to servers
    speakSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    speakSkt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Connect to the server
    speakSkt.connect((hostName, serverPort))
    # send http request
    sendMsgToSocket(speakSkt, conditionalHttpRequest)
    
    # Receive data from origin server
    totalNewData = b''
    firstData = True
    saveToCache = True
    threadLock.acquire()  # lock
    try:
        while True:  # while not done with the server connection
            newData = speakSkt.recv(2048)
            if firstData:
                firstData = False
                #If the object has not been modified since the last retrieval, send the cached copy to the client
                try:
                    if "304 Not Modified" in newData.decode():
                        saveToCache = False
                        clientSkt.sendall(cache[getRequest])
                        break

                    #If the object does not have 200 OK as a response, do not save it to the cache
                    if not ("200 OK" in newData.decode()):
                        saveToCache = False
                except:  #An error occurred with decoding; therefore, assume we cannot cache the data
                    saveToCache = False
            
            #The original object HAS been modified - send incoming data back to client
            clientSkt.sendall(newData)
            try:
                totalNewData += bytearray(newData) #Append all found data to larger string
            except:
                totalNewData = bytearray(newData)
                saveToCache = False
            if newData == b'':
                break
    finally:
        threadLock.release()  # unlock
    speakSkt.close()
    
    if saveToCache:
        cache[getRequest] = totalNewData #Add the retrieved data to the cache

'''
# domainBlockProtocol(getRequest):  Given a full GET request, this function checks if the GET 
# request cannot be sent to a server due to the host, port, or host:port combination being on the
# blocklist. The proxy will not contact the server if any of these are in the blocklist.
# 
# PARAMS:
# getRequest - The unmodified GET request sent from the current client.
# 
# RETURN VALUE: 
# A boolean value indicated if the specified getRequest is in the blocklist. This returns True
# if part of the GET request is on the blocklist. This returns False if it isn't on the blocklist.
'''
def domainBlockProtocol(getRequest):
    
    global blocklistIsEnabled #Make sure to use the global version of blocklistIsEnabled
    global blocklist #Make sure to use the global version of blocklist

    #Return values is if the value is in the blocklist and, if it is, the value to send to the client
    #Check if the blocklist is enabled. If not, return pre-emptively.
    if not blocklistIsEnabled:
        return False
    #Else, get host from GET request
    hostAndPort = getHostNameAndPort(getRequest)
    port = hostAndPort[1]
    
    #Parse hostname more to just have the host
    host = (hostAndPort[0].split("http://")[0])
    if host.startswith("www."): #www is optional; remove www if it's there
        host = host.split("www.")[0]
    host = host.split(".")[0]
    hostPortCombo = host + ":" + str(port)

    if hostName in blocklist: #Check if the host is blocked
        return True
    elif port in blocklist: #Check if the port is blocked
        return True
    elif hostPortCombo in blocklist: #Check if the host:port combination is blocked
        return True
    else:
        return False #Nothing with the current GET request is blocked

'''
# cacheBlocklistControl(getRequestPath): Given the absolute path from the client's GET request, we check
# if it matches any of the paths specified from our cache and blocklist control interface. If it matches
# any of them, we follow the specific protocol for that path.
# 
# PARAMS:
# getRequestPath - The absolute path from the current client's GET request. This is not the
# full GET request.
# 
# RETURN VALUE: 
# specialRequestPath - A boolean value indicating if getRequestPath did match any of the cache/blocklist 
# control requests. It returns True if so, and the proxy will not enact client-server communication in other
# parts of the program. It returns False if nothing matched, and it indicates to our proxy to treat the GET
# request as a normal GET request.
'''
def cacheBlocklistControl(getRequestPath):
    global cacheIsEnabled
    global blocklist
    global cache
    global blocklistIsEnabled

    specialRequestPath = False # Changes every time there is a valid read of any of the absolute paths
    
    #Enable the proxy’s cache; if it is already enabled, do nothing.
    if "/proxy/cache/enable" == getRequestPath:
        specialRequestPath = True
        if cacheIsEnabled == False:
            cacheIsEnabled = True
    #Disable the proxy’s cache; if it is already disabled, do nothing.
    elif "/proxy/cache/disable" == getRequestPath:
        specialRequestPath = True
        if cacheIsEnabled == True:
            cacheIsEnabled = False
    #Flush (empty) the proxy’s cache.
    elif "/proxy/cache/flush" == getRequestPath:
        specialRequestPath = True
        cache = {}
    #Enable the proxy’s blocklist; if it is already enabled, do nothing.
    elif "/proxy/blocklist/enable" == getRequestPath:
        specialRequestPath = True
        if blocklistIsEnabled == False:
            blocklistIsEnabled = True
    #Disable the proxy’s blocklist; if it is already disabled, do nothing. 
    elif "/proxy/blocklist/disable" == getRequestPath:
        specialRequestPath = True
        if blocklistIsEnabled == True:
            blocklistIsEnabled = False
    #Add the specified string to the proxy’s blocklist; if it is already in the blocklist, do nothing.
    elif "/proxy/blocklist/add/" in getRequestPath:
        specialRequestPath = True
        addStr = getRequestPath.split("/proxy/blocklist/add/")[0]
        if not (addStr in blocklist):
            blocklist.append(addStr)
    #Remove the specified string from the proxy’s blocklist; if it is not already in the blocklist, do nothing.
    elif "/proxy/blocklist/remove/" in getRequestPath:
        specialRequestPath = True
        removeStr = getRequestPath.split("/proxy/blocklist/remove/")[0]
        if removeStr in blocklist:
            blocklist.remove(removeStr)
    #Flush (empty) the proxy’s blocklist. This request does not affect the enabled/disabled state of the blocklist.
    elif "/proxy/blocklist/flush" == getRequestPath:
        specialRequestPath = True
        blocklist = []
    return specialRequestPath
    
'''
# sendMsgToSocket(skt, data): This function sends something (data) to the specified socket (skt).
# 
# PARAMS:
# skt - The socket of what we are communicating with. It is either the client's socket or the server's socket.
# data - The message that must be sent to the socket.
# 
# RETURN VALUE: 
# [None]
'''
def sendMsgToSocket(skt, data):
    threadLock.acquire()  # lock
    try:
        skt.sendall(data.encode())
    finally:
        threadLock.release()  # unlock

'''
# sendAndReceiveServerData(getRequest): This function creates a connection with the specified
# server from the provided GET request, receives the server's response, and relays the response 
# back to the client. If applicable, the data is stored in the cache.
# 
# PARAMS:
# getRequestPath - The unmodified GET request sent from the current client.
# 
# RETURN VALUE: 
# [None]
'''
def sendAndReceiveServerData(getRequest):
    
    global cache #Ensure the global cache variable is used
    global cacheIsEnabled #Ensure the global cacheIsEnabled variable is used
    # Parse GET request into HTTPRequest
    hostName, serverPort = getHostNameAndPort(getRequest)
    httpRequest = parseGetRequest(getRequest, False)
    
    # Initialize the proxy-client (speaking) socket, it will speak to servers
    speakSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    speakSkt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Connect to the server
    speakSkt.connect((hostName, serverPort))
    # send http request
    sendMsgToSocket(speakSkt, httpRequest)

    # Receive data from origin server
    totalNewData = b''
    firstData = True
    saveToCache = True
    threadLock.acquire()  # lock
    try:
        while True:  # while not done with the server connection
            newData = speakSkt.recv(2048)
            
            #If the object does not have 200 OK as a response, do not save it to the cache
            if firstData:
                firstData = False
                if not cacheIsEnabled: #if the cache isn't enabled, do not save to the cache
                    saveToCache = False
                try:
                    if not ("200 OK" in newData.decode()):
                        saveToCache = False
                except: #An error occurred with decoding; therefore, assume we cannot cache the data
                    saveToCache = False
            
            # Send data back to client
            clientSkt.sendall(newData)
            try:
                totalNewData += bytearray(newData) #Append all found data to larger string
            except:
                totalNewData = bytearray(newData)
            if newData == b'':
                break
    finally:
        threadLock.release()  # unlock
    speakSkt.close()
    
    if saveToCache:
        cache[getRequest] = totalNewData #Add the retrieved data to the cache 

'''
# clientConnection(clientSkt, threadLock): This function handles creating the connection with a new client.
# It receives the GET request from the client and handles it differently depending on the contents of the 
# GET request. It checks the domain blocklist and cache protocols appropriately, and it initiates direct 
# client-server communication only in certain cases.
# 
# PARAMS:
# clientSkt: The socket of the client, which is used for the proxy to communicate with the client.
# threadLock: The threading lock used for lock/unlocking certain parts of the program execution, which 
# ultimately protects the program from race conditions and other problematic multithreading issues.
# 
# RETURN VALUE: 
# [None]
'''
def clientConnection(clientSkt, threadLock):
    
    global cache #Ensure the global cache variable is used
    
    with clientSkt as clientSkt:
        # Receive GET request and decode it into a string object
        getRequest = ""
        while True:
            getRequest += clientSkt.recv(2048).decode()
            if getRequest.endswith("\r\n\r\n"):
                break

        # Check if the GET request is valid
        req = checkRequestValidity(getRequest)
        print("Req value: ", req)
        if req == "GET": #Valid GET request continues the program as normal
            #Domain Block Handling --
            #If the GET request is blocked somehow, the client receives a 403 Forbidden error
            isBlocked = domainBlockProtocol(getRequest)
            if isBlocked:
                threadLock.acquire()  # lock
                try:
                    clientSkt.sendall("403 Forbidden\n".encode())
                finally:
                    threadLock.release()  # unlock
            #Cache Handling --
            #If the object is currently in the cache (and the cache is enabled), we will use the
            #specified cache protocol to respond with the most up-to-date version of the object.
            elif (getRequest in cache) and (cacheIsEnabled):
                    cacheProtocol(getRequest)
            else: #Object is not in the cache nor blocked; send a regular GET request to the origin server
                    sendAndReceiveServerData(getRequest)
        elif req == "SPECIALREQ": #If the absolute path had a special request, do not send anything to the client
            return
        else: #Invalid GET request ends the connection prematurely
            sendMsgToSocket(clientSkt, req)


# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100

# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

# Initialize the proxy-server (listening) socket, it will listen for new clients
listenSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listenSkt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listenSkt.bind((address, port))
listenSkt.listen()

# Create a lock for eventual multithreading handling
threadLock = threading.Lock()

hostName = ""
httpRequest = ""
while True: #This never breaks; it keeps the proxy program running instead of ending prematurely
    while True: #This keeps the proxy listening for new client connections
        # Accept connection from a client
        clientSkt, clientAddr = listenSkt.accept()

        # Handle each connection in a separate thread
        threading.Thread(target=clientConnection, args=(clientSkt, threadLock)).start()
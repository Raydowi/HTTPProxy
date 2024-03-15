# Uni-Projects: Simple HTTP Web Proxy

 Last Updated: February 12th, 2023
 Course Info: University of Utah - CS4480-001 Computer Networks - Spring 2023 
 Author(s): Ray Parker
 
 Instructions: Run "python3 HTTPproxy.py" from the terminal and, in a different terminal (on the same computer), run "telnet localhost <port>"
 to test the program's functionalities. If running on CADE, run on port 2100.

 This is a simple HTTP Web Proxy that handles communicate between the client (browser) and the server (web server). This
 is an HTTP/1.0 web proxy with basic object-caching and domain-blocking features, and it additionally handles multiple
 concurrent requests at any given time. Here is a summary of the tested functionalities for this project:

    - Only works with GET HTTP methods through HTTP 1.0. Malformed headers + requests, non-GET HTTP methods, malformed URIs, and wrong HTTP versions are denied.
    
    - Consistently handles communication between clients and websevers, including large server responses that may not fit in a single buffer.
    
    - When the client provides GET headers, the proxy parses and creates GET requests to send to the appropriate server. Any malformed GET requests are returned with an error.
    
    - Handles consecutive requests without dying, returns intended webpages from webservers, and forwards server responses to clients without modification.
    
    - Properly handles concurrent connections using multi-threading. The proxy can handle hanging connections, slow connections, and responsive connections at the same time. Additionally, it has been stress tested to receive multiple concurrent requests and still function as intended.
    
    - Utilizes local cache functionalities to improve performance. When a web request is made, the server's response is stored locally, so the proxy can respond with the server's request without having to connect to the server for future client requests. In this case, conditional GETs are sent to the server instead to make sure the object has not been modified since the request was cached. The cache can be enabled or disabled, and the cache can be flushed at any time as well. The saved blocklist is not lost when switching between enabled/disabled states.
    
    - Utilizes blocklist functionalities. If the client tries to connect to a server within the blocklist, the proxy does not actually connect the server and instead sends a "403 Forbidden" response. The blocklist can be enabled or disabled, and the blocklist can be flushed at any time. Additionally, items can be individually added and removed from the blocklist at any time. The saved blocklist is not lost when switching between enabled/disabled states.



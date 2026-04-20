"""HTTP Honeypot - Emulates web server on port 8080"""

import socket
import threading
import logging
from core.event_queue import event_queue

logger = logging.getLogger(__name__)

class HTTPHoneypot:
    """HTTP Honeypot Server"""
    
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.running = False
        self.server = None
    
    def start(self):
        """Start HTTP honeypot"""
        self.running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        logger.info(f"HTTP Honeypot listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                client, addr = self.server.accept()
                threading.Thread(target=self.handle_connection, args=(client, addr)).start()
            except:
                break
    
    def handle_connection(self, client, addr):
        """Handle HTTP connection"""
        try:
            request = client.recv(4096).decode('utf-8', errors='ignore')
            
            if request:
                lines = request.split('\r\n')
                method_line = lines[0] if lines else ''
                
                event_queue.put({
                    'type': 'http_request',
                    'source_ip': addr[0],
                    'source_port': addr[1],
                    'method': method_line.split()[0] if method_line else 'UNKNOWN',
                    'path': method_line.split()[1] if len(method_line.split()) > 1 else '/',
                    'payload': request
                })
                
                response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>OK</body></html>"
                client.send(response)
            
            client.close()
        except:
            pass
    
    def stop(self):
        """Stop HTTP honeypot"""
        self.running = False
        if self.server:
            self.server.close()

http_honeypot = HTTPHoneypot()

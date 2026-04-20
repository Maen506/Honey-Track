"""SSH Honeypot - Emulates SSH server on port 2222"""

import socket
import threading
import logging
from core.event_queue import event_queue

logger = logging.getLogger(__name__)

class SSHHoneypot:
    """SSH Honeypot Server"""
    
    def __init__(self, host='0.0.0.0', port=2222):
        self.host = host
        self.port = port
        self.running = False
        self.server = None
    
    def start(self):
        """Start SSH honeypot"""
        self.running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        logger.info(f"SSH Honeypot listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                client, addr = self.server.accept()
                threading.Thread(target=self.handle_connection, args=(client, addr)).start()
            except:
                break
    
    def handle_connection(self, client, addr):
        """Handle SSH connection"""
        try:
            client.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            
            event_queue.put({
                'type': 'ssh_connection',
                'source_ip': addr[0],
                'source_port': addr[1],
                'action': 'connection_received'
            })
            
            client.close()
        except:
            pass
    
    def stop(self):
        """Stop SSH honeypot"""
        self.running = False
        if self.server:
            self.server.close()

ssh_honeypot = SSHHoneypot()

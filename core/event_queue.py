"""
Event Queue - Bridge between all components
Thread-safe queue for inter-component communication
"""

import queue
import threading
from datetime import datetime
from typing import Dict, Any, Optional

class EventQueue:
    """Thread-safe event queue for component communication"""
    
    def __init__(self, max_size=10000):
        self.queue = queue.Queue(maxsize=max_size)
        self.lock = threading.Lock()
        self.event_count = 0
    
    def put(self, event: Dict[str, Any]) -> bool:
        """Add event to queue"""
        try:
            event['timestamp'] = datetime.now().isoformat()
            self.queue.put(event, timeout=1)
            with self.lock:
                self.event_count += 1
            return True
        except queue.Full:
            return False
    
    def get(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Get event from queue"""
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def size(self) -> int:
        """Get queue size"""
        return self.queue.qsize()
    
    def stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        with self.lock:
            return {
                'size': self.size(),
                'total_events': self.event_count
            }

# Global event queue instance
event_queue = EventQueue()

from collections import deque
import threading
from typing import Optional
from core.evidence.event import EvidenceEvent, PRIORITY_VALUES, EventStatus

class EventQueue:
    """An in-memory, thread-safe queue for EvidenceEvents.

    Prioritizes events based on EventPriority, falling back to chronological FIFO
    order for events of the same priority level.
    """

    def __init__(self, max_size: int = 10000):
        self._deque = deque(maxlen=max_size)
        self.lock = threading.Lock()

    def enqueue(self, event: EvidenceEvent) -> bool:
        """Enqueues an event. Returns True if successful, False if queue is full."""
        with self.lock:
            if len(self._deque) >= (self._deque.maxlen or 10000):
                return False
            event.status = EventStatus.QUEUED
            self._deque.append(event)
            return True

    def dequeue(self) -> Optional[EvidenceEvent]:
        """Dequeues the highest priority event.

        If multiple events have the highest priority, the oldest one is returned (FIFO).
        Returns None if queue is empty.
        """
        with self.lock:
            if not self._deque:
                return None
            
            # Find the index of the highest priority event
            # Tie breaker: oldest event (closest to index 0)
            highest_priority_idx = 0
            highest_priority_val = PRIORITY_VALUES[self._deque[0].priority]
            
            for i, event in enumerate(self._deque):
                priority_val = PRIORITY_VALUES[event.priority]
                if priority_val > highest_priority_val:
                    highest_priority_val = priority_val
                    highest_priority_idx = i
            
            # Pop the selected event from the middle of the deque
            event = self._deque[highest_priority_idx]
            
            # Rotate, popleft, and rotate back to remove from arbitrary index
            self._deque.rotate(-highest_priority_idx)
            self._deque.popleft()
            self._deque.rotate(highest_priority_idx)
            
            event.status = EventStatus.PROCESSING
            return event

    def peek(self) -> Optional[EvidenceEvent]:
        """Peeks at the next event that dequeue would return, without removing it."""
        with self.lock:
            if not self._deque:
                return None
            
            highest_priority_idx = 0
            highest_priority_val = PRIORITY_VALUES[self._deque[0].priority]
            
            for i, event in enumerate(self._deque):
                priority_val = PRIORITY_VALUES[event.priority]
                if priority_val > highest_priority_val:
                    highest_priority_val = priority_val
                    highest_priority_idx = i
                    
            return self._deque[highest_priority_idx]

    def size(self) -> int:
        """Returns the current size of the queue."""
        with self.lock:
            return len(self._deque)

    def clear(self) -> None:
        """Clears all events in the queue."""
        with self.lock:
            self._deque.clear()

    def is_empty(self) -> bool:
        """Returns True if the queue is empty, False otherwise."""
        with self.lock:
            return len(self._deque) == 0

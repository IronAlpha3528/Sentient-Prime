import uuid
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
import pandas as pd

from sentinel_prime.detection.detectors.endpoint.schemas import EndpointEvent

logger = logging.getLogger(__name__)

def parse_timestamp(ts_str: str) -> datetime:
    try:
        dt = pd.to_datetime(ts_str)
        if dt.tzinfo is not None:
            dt = dt.tz_convert('UTC').tz_localize(None)
        return dt.to_pydatetime()
    except Exception:
        return datetime.utcnow()

def build_process_windows(events: List[EndpointEvent], window_duration_seconds: int = 60) -> List[Dict[str, Any]]:
    """
    Groups events by Host and Process entity, then partitions them into temporal windows.
    Each window contains:
      - window_id
      - host
      - process
      - parent_process
      - window_start
      - window_end
      - event_count
      - events (List[EndpointEvent])
    """
    if not events:
        return []

    # Step 1: Group events by host and process identifier (Process ID + Process Name)
    # We use a compound key: (host, process_id, process_name)
    # If process_id is missing, we use -1. If process_name is missing, we use "unknown".
    groups: Dict[Tuple[str, int, str], List[EndpointEvent]] = {}
    
    for ev in events:
        h = ev.host or "unknown_host"
        pid = ev.process_id if ev.process_id is not None else -1
        pname = ev.process_name or "unknown_process"
        
        # Also resolve relationships: if it is Event ID 1 (Process Create),
        # we can establish parent relationships.
        key = (h, pid, pname)
        if key not in groups:
            groups[key] = []
        groups[key].append(ev)

    windows = []
    duration = timedelta(seconds=window_duration_seconds)

    for (host, pid, pname), grp_events in groups.items():
        # Sort group events by timestamp
        sorted_events = sorted(grp_events, key=lambda e: parse_timestamp(e.timestamp or ""))
        
        # Segment into temporal windows
        current_window_events: List[EndpointEvent] = []
        window_start_time: Optional[datetime] = None
        window_index = 0

        for ev in sorted_events:
            ev_time = parse_timestamp(ev.timestamp or "")
            
            if window_start_time is None:
                window_start_time = ev_time
                current_window_events.append(ev)
            elif ev_time - window_start_time <= duration:
                current_window_events.append(ev)
            else:
                # Flush the current window
                windows.append(create_window_dict(
                    host, pname, pid, current_window_events, window_start_time, window_index
                ))
                # Start new window
                window_index += 1
                window_start_time = ev_time
                current_window_events = [ev]
                
        # Flush the final window for this group
        if current_window_events and window_start_time:
            windows.append(create_window_dict(
                host, pname, pid, current_window_events, window_start_time, window_index
            ))

    return windows

def create_window_dict(
    host: str,
    process_name: str,
    process_id: int,
    events: List[EndpointEvent],
    start_time: datetime,
    index: int
) -> Dict[str, Any]:
    # Determine the parent process from the events in this window (or from the first process creation event)
    parent_process = None
    for ev in events:
        if ev.parent_process_name:
            parent_process = ev.parent_process_name
            break

    # If no parent process is explicitly logged in the events, check for sysmon pid relationships
    # without fabricating names.
    
    end_time = parse_timestamp(events[-1].timestamp or "")
    
    # Standard format: {host}_{process}_{pid}_{index}
    window_id = f"{host}_{process_name}_{process_id}_{index}_{uuid.uuid4().hex[:6]}"
    
    return {
        "window_id": window_id,
        "host": host,
        "process": process_name,
        "parent_process": parent_process,
        "window_start": start_time.isoformat(),
        "window_end": end_time.isoformat(),
        "event_count": len(events),
        "events": events
    }

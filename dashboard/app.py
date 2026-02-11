"""
GuardianX Dashboard — FastAPI Backend
Provides REST API endpoints and WebSocket real-time event streaming.
"""

import json
import asyncio
import threading
import logging
from datetime import datetime
from pathlib import Path
from collections import deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse

# Resolve paths
DASHBOARD_DIR = Path(__file__).parent
STATIC_DIR = DASHBOARD_DIR / 'static'

logger = logging.getLogger("GuardianX.Dashboard")

# ─── Shared Event Bus ─────────────────────────────────────────────────────
# Thread-safe event queue shared between GuardianX engine and dashboard

class EventBus:
    """Thread-safe event bus for sharing events between engine and dashboard."""
    
    def __init__(self, max_history=500):
        self._subscribers = []
        self._lock = threading.Lock()
        self.event_history = deque(maxlen=max_history)
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'processes_killed': 0,
            'processes_suspended': 0,
            'start_time': datetime.now().isoformat(),
            'monitoring_mode': 'Initializing...',
        }
    
    def publish(self, event):
        """Publish an event to all subscribers."""
        event['timestamp'] = event.get('timestamp', datetime.now().isoformat())
        self.event_history.append(event)
        
        with self._lock:
            for callback in self._subscribers:
                try:
                    callback(event)
                except Exception:
                    pass
    
    def subscribe(self, callback):
        with self._lock:
            self._subscribers.append(callback)
    
    def unsubscribe(self, callback):
        with self._lock:
            self._subscribers = [s for s in self._subscribers if s is not callback]
    
    def get_history(self, limit=100, event_type=None):
        history = list(self.event_history)
        if event_type:
            history = [e for e in history if e.get('type') == event_type]
        return history[-limit:]
    
    def update_stats(self, **kwargs):
        self.stats.update(kwargs)


# Global event bus instance
event_bus = EventBus()


# ─── FastAPI Application ──────────────────────────────────────────────────

app = FastAPI(
    title="GuardianX Dashboard",
    description="Real-time ransomware defense monitoring",
    version="2.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Active WebSocket connections
ws_connections = set()


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the dashboard HTML."""
    index_path = STATIC_DIR / 'index.html'
    return FileResponse(str(index_path))


@app.get("/api/status")
async def get_status():
    """Get current GuardianX system status."""
    return {
        'status': 'active',
        'stats': event_bus.stats,
        'active_connections': len(ws_connections),
        'event_queue_size': len(event_bus.event_history),
    }


@app.get("/api/threats")
async def get_threats(limit: int = 50):
    """Get recent threat events."""
    threats = event_bus.get_history(limit=limit, event_type='threat')
    
    # Also read from disk logs as fallback
    if not threats:
        threats = _read_log_file('threats')
    
    return {'threats': threats, 'total': len(threats)}


@app.get("/api/timeline")
async def get_timeline(hours: int = 24):
    """Get attack timeline data for visualization."""
    events = event_bus.get_history(limit=1000)
    
    # Group events by hour for timeline chart
    timeline = {}
    for event in events:
        ts = event.get('timestamp', '')
        if ts:
            hour_key = ts[:13]  # YYYY-MM-DDTHH
            if hour_key not in timeline:
                timeline[hour_key] = {'threats': 0, 'events': 0, 'kills': 0, 'suspends': 0}
            timeline[hour_key]['events'] += 1
            if event.get('type') == 'threat':
                timeline[hour_key]['threats'] += 1
            if event.get('action') == 'KILL':
                timeline[hour_key]['kills'] += 1
            if event.get('action') == 'SUSPEND':
                timeline[hour_key]['suspends'] += 1
    
    return {'timeline': timeline}


@app.get("/api/stats")
async def get_aggregate_stats():
    """Get aggregate statistics."""
    return {
        'stats': event_bus.stats,
        'history_size': len(event_bus.event_history),
        'threat_count': len([e for e in event_bus.event_history if e.get('type') == 'threat']),
    }


@app.get("/api/events")
async def get_events(limit: int = 100, event_type: str = None):
    """Get recent events with optional type filter."""
    events = event_bus.get_history(limit=limit, event_type=event_type)
    return {'events': events}


@app.post("/api/restore/{filepath:path}")
async def restore_file(filepath: str):
    """Trigger file restore from backup."""
    try:
        from file_recovery import FileRecoveryManager
        recovery = FileRecoveryManager()
        success, message = recovery.restore_file(filepath)
        return {'success': success, 'message': message}
    except Exception as e:
        return {'success': False, 'message': str(e)}


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming."""
    await websocket.accept()
    ws_connections.add(websocket)
    
    logger.info(f"WebSocket client connected ({len(ws_connections)} total)")
    
    # Send recent history on connect
    try:
        history = event_bus.get_history(limit=50)
        await websocket.send_json({
            'type': 'history',
            'events': history,
            'stats': event_bus.stats,
        })
    except Exception:
        pass
    
    # Set up event forwarding
    event_queue = asyncio.Queue()
    
    def on_event(event):
        try:
            event_queue.put_nowait(event)
        except Exception:
            pass
    
    event_bus.subscribe(on_event)
    
    try:
        while True:
            # Wait for events (with timeout for keepalive)
            try:
                event = await asyncio.wait_for(event_queue.get(), timeout=15.0)
                await websocket.send_json({
                    'type': 'event',
                    'event': event,
                    'stats': event_bus.stats,
                })
            except asyncio.TimeoutError:
                # Send keepalive ping
                await websocket.send_json({
                    'type': 'ping',
                    'stats': event_bus.stats,
                })
            
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"WebSocket error: {e}")
    finally:
        ws_connections.discard(websocket)
        event_bus.unsubscribe(on_event)
        logger.info(f"WebSocket client disconnected ({len(ws_connections)} remaining)")


# ─── Helpers ──────────────────────────────────────────────────────────────

def _read_log_file(log_type):
    """Read events from JSON log files."""
    import os
    log_dir = Path(os.getenv('TEMP')) / 'GuardianX' / 'logs'
    
    type_map = {
        'threats': 'threats.json',
        'suspended': 'suspended.json',
        'activity': 'activity.json',
    }
    
    filename = type_map.get(log_type)
    if not filename:
        return []
    
    log_path = log_dir / filename
    try:
        if log_path.exists():
            with open(log_path, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return []


def start_dashboard(host="0.0.0.0", port=9090):
    """Start the dashboard server in a background thread."""
    import uvicorn
    
    def run():
        uvicorn.run(app, host=host, port=port, log_level="warning")
    
    thread = threading.Thread(target=run, daemon=True, name="GuardianX-Dashboard")
    thread.start()
    logger.info(f"Dashboard server started at http://{host}:{port}")
    return thread

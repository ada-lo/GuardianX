"""GuardianX Dashboard — Real-time web UI."""

from guardianx.dashboard.app import app, event_bus, start_dashboard

__all__ = ['app', 'event_bus', 'start_dashboard']

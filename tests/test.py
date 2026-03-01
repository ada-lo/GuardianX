import win32event
signal_event = win32event.CreateEvent(None, False, False, None)

print(type(signal_event))

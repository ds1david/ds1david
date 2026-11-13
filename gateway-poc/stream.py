"""Bounded bidirectional transport for the loopback echo fixture only."""
import socket
import threading
import time

MAX_BYTES = 1024 * 1024
MAX_SECONDS = 60
IDLE_SECONDS = 10


def relay(left, right, max_bytes=MAX_BYTES, max_seconds=MAX_SECONDS, idle_seconds=IDLE_SECONDS):
    stop = threading.Event()
    lock = threading.Lock()
    state = {'bytes': 0, 'activity': time.monotonic(), 'reason': 'closed'}
    deadline = time.monotonic() + max_seconds
    left.settimeout(1)
    right.settimeout(1)

    def pump(source, destination):
        try:
            while not stop.is_set():
                now = time.monotonic()
                with lock:
                    if now >= deadline or now - state['activity'] >= idle_seconds:
                        state['reason'] = 'timeout'
                        break
                try:
                    data = source.recv(16384)
                except socket.timeout:
                    continue
                if not data:
                    break
                with lock:
                    if state['bytes'] + len(data) > max_bytes:
                        state['reason'] = 'byte_limit'
                        break
                    state['bytes'] += len(data)
                    state['activity'] = time.monotonic()
                destination.sendall(data)
        except OSError:
            with lock:
                state['reason'] = 'disconnected'
        finally:
            stop.set()

    workers = [threading.Thread(target=pump, args=pair, daemon=True)
               for pair in ((left, right), (right, left))]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(max_seconds + 3)
    return state['reason'], state['bytes']

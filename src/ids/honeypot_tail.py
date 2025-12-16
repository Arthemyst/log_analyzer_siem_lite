import json
import time

class HoneypotTail:
    """
    Simple tail -f reader for honeypot_events.jsonl
    """

    def __init__(self, path: str):
        self.path = path
        self._fp = open(self.path, "r", encoding="utf-8")
        self._fp.seek(0, 2)  # EOF

    def poll(self):
        """
        Returns list of new honeypot events.
        """
        events = []

        while True:
            line = self._fp.readline()
            if not line:
                break

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

        return events
    
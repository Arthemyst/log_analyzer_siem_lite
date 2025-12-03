import asyncio
import logging
from exporter import validate_rfc5424_message
from datetime import datetime
logger = logging.getLogger("SyslogReceiver")
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler("receiver.log")
formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

async def process_syslog_message(msg: str, protocol: str):
    msg_preview = msg[:80].replace("\n", " ")
    logger.info(f"[RECV-{protocol}] Received: {msg_preview}")

    if validate_rfc5424_message(msg):
        logger.info(f"[RECV-{protocol}] RFC5424 OK")
    else:
        logger.warning(f"[RECV-{protocol}] INVALID RFC5424")

    with open("received_syslog.log", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} | {protocol} | {msg}\n")

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        message = data.decode(errors="ignore")
        asyncio.create_task(process_syslog_message(message, "UDP"))

class SyslogTCPClientHandler(asyncio.Protocol):
    def __init__(self):
        self.buffer = b""

    def data_received(self, data: bytes):
        self.buffer += data

        while True:
            if b" " not in self.buffer:
                return

            try:
                length_str, rest = self.buffer.split(b" ", 1)
                if not length_str.isdigit():
                    logger.warning(f"[TCP] Invalid length prefix")
                    self.buffer = b""
                    return

                msg_len = int(length_str)
            except ValueError:
                return

            if len(rest) < msg_len:
                return

            raw_msg = rest[:msg_len].decode(errors="ignore")
            self.buffer = rest[msg_len:]

            asyncio.create_task(process_syslog_message(raw_msg, "TCP"))

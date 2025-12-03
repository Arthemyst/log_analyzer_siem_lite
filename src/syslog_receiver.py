import asyncio
import logging
from .exporter import validate_rfc5424_message
from datetime import datetime

pipeline = None

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

    if pipeline:
        pipeline.handle_message(msg)

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

async def run_syslog_receiver(
        udp_port: int = 514,
        tcp_port: int = 514,
        host: str = "0.0.0.0",
):
    loop = asyncio.get_running_loop()

    #UDP
    logger.info(f"[START] Starting UDP syslog server on {host}:{udp_port}")
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(),
        local_addr=(host, udp_port),
    )

    #TCP
    logger.info(f"[START] Starting TCP syslog server on {host}:{tcp_port}")
    tcp_server = await loop.create_server(
        lambda: SyslogTCPClientHandler(),
        host,
        tcp_port,
    )

    async with tcp_server:
        logger.info(f"[READY] Syslog receiver running (UDP + TCP).")
        await tcp_server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(run_syslog_receiver())
    except KeyboardInterrupt:
        logger.info(f"[STOP] Syslog receiver stopped manually.")

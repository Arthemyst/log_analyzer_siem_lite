import logging

logger = logging.getLogger("SyslogReceiver")
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler("receiver.log")
formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

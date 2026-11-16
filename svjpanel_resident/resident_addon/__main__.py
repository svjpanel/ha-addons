import logging
import sys
import time

from .runner import run

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

if __name__ == "__main__":
    while True:
        code = run()
        if code in (2, 3, 4):
            logging.getLogger("resident_addon").error("stopped (code %s)", code)
            sys.exit(code)
        time.sleep(30)

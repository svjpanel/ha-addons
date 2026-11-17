import logging
import sys
import time

from .runner import run

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

if __name__ == "__main__":
    while True:
        try:
            code = run()
        except Exception:  # noqa: BLE001
            logging.getLogger("resident_addon").exception("unexpected error; restarting")
            code = 1
        if code in (2, 3, 4):
            logging.getLogger("resident_addon").error("stopped (code %s)", code)
            sys.exit(code)
        time.sleep(30)

import logging
import time
import threading
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .base import Notifier

logger = logging.getLogger(__name__)

# Shared dedup tracker: only one Telegram instance should exist per process,
# but the lock lives here so ConsoleNotifier can import Notifier cleanly.
_last_processed_update_id_lock = threading.Lock()
_last_processed_update_id = [0]


class TelegramNotifier(Notifier):
    """
    Delivers alerts and collects human-in-the-loop authorization via the
    Telegram Bot API.  Functionally identical to the original inline code in
    live_sentinel.py — just properly encapsulated.
    """

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._base_url = f"https://api.telegram.org/bot{bot_token}"

    # ------------------------------------------------------------------
    # Notifier interface
    # ------------------------------------------------------------------

    def send_alert(self, message: str, photo_path: str = None) -> bool:
        if photo_path:
            return self._send_photo(photo_path, caption=message)
        return self._send_message(message)

    def request_authorization(
        self,
        prompt: str | None,
        timeout_sec: int = 90,
        accept_ignore: bool = False,
    ) -> str:
        if prompt:
            self.send_alert(prompt)

        logger.info("[Telegram] Waiting for admin reply...")

        url = f"{self._base_url}/getUpdates"
        try:
            init = requests.get(url, verify=False, timeout=10).json()
            last_id = 0
            if init.get("ok") and init["result"]:
                last_id = init["result"][-1]["update_id"]
                with _last_processed_update_id_lock:
                    _last_processed_update_id[0] = last_id
        except Exception:
            last_id = 0

        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            time.sleep(2)
            try:
                resp = requests.get(
                    f"{url}?offset={last_id + 1}&timeout=5",
                    verify=False,
                    timeout=10,
                ).json()
                if resp.get("ok") and resp["result"]:
                    for update in resp["result"]:
                        last_id = update["update_id"]
                        if "message" not in update or "text" not in update["message"]:
                            continue
                        text = update["message"]["text"].strip().upper()
                        if text == "YES":
                            with _last_processed_update_id_lock:
                                if update["update_id"] <= _last_processed_update_id[0]:
                                    continue
                                _last_processed_update_id[0] = update["update_id"]
                            return "YES"
                        if text == "IGNORE" and accept_ignore:
                            return "IGNORE"
            except Exception:
                pass

        return "TIMEOUT"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_message(self, text: str) -> bool:
        try:
            res = requests.post(
                f"{self._base_url}/sendMessage",
                json={"chat_id": self.chat_id, "text": text},
                verify=False,
                timeout=15,
            )
            logger.debug(f"[Telegram] sendMessage {res.status_code}")
            return res.status_code == 200
        except requests.exceptions.Timeout:
            logger.warning("[Telegram] sendMessage timed out")
            return False
        except Exception as e:
            logger.error(f"[Telegram] sendMessage error: {e}")
            return False

    def _send_photo(self, photo_path: str, caption: str = "") -> bool:
        try:
            with open(photo_path, "rb") as f:
                res = requests.post(
                    f"{self._base_url}/sendPhoto",
                    data={"chat_id": self.chat_id, "caption": caption},
                    files={"photo": f},
                    verify=False,
                    timeout=15,
                )
            logger.debug(f"[Telegram] sendPhoto {res.status_code}")
            if res.status_code != 200:
                return self._send_message(caption)
            return True
        except requests.exceptions.Timeout:
            logger.warning("[Telegram] sendPhoto timed out — falling back to text")
            return self._send_message(caption)
        except Exception as e:
            logger.error(f"[Telegram] sendPhoto error: {e}")
            return self._send_message(caption)

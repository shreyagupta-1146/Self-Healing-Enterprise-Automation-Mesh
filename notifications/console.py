import logging

from .base import Notifier

logger = logging.getLogger(__name__)


class ConsoleNotifier(Notifier):
    """
    Fallback notifier for dev/test environments with no external channel.
    Prints alerts to stdout and reads admin decisions from stdin.
    Identical behaviour to the old TELEGRAM_BOT_TOKEN == 'YOUR_TOKEN' branch.
    """

    def send_alert(self, message: str, photo_path: str = None) -> bool:
        print(f"\n\033[93m[CONSOLE ALERT]\033[0m {message}")
        if photo_path:
            print(f"  (attached: {photo_path})")
        return True

    def request_authorization(
        self,
        prompt: str | None,
        timeout_sec: int = 90,
        accept_ignore: bool = False,
    ) -> str:
        if prompt:
            self.send_alert(prompt)
        print("\033[93m[CONSOLE AUTH]\033[0m Type YES, IGNORE, or press Enter to simulate TIMEOUT:")
        try:
            ans = input(">> ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans == "YES":
            return "YES"
        if ans == "IGNORE" and accept_ignore:
            return "IGNORE"
        return "TIMEOUT"

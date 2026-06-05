from abc import ABC, abstractmethod


class Notifier(ABC):
    """
    Abstract notification + human-in-the-loop authorization channel.
    Concrete backends: TelegramNotifier, ConsoleNotifier, AegisNotifier.
    """

    @abstractmethod
    def send_alert(self, message: str, photo_path: str = None) -> bool:
        """
        Send an alert message, optionally with an attached image.
        Returns True on successful delivery.
        """

    @abstractmethod
    def request_authorization(
        self,
        prompt: str | None,
        timeout_sec: int = 90,
        accept_ignore: bool = False,
    ) -> str:
        """
        Send prompt (if not None) then block until an admin responds or timeout.
        Returns: "YES" | "IGNORE" | "TIMEOUT"
        "IGNORE" is only returned when accept_ignore=True and the admin sent it.
        """

    def send_summary(self, message: str) -> bool:
        """Convenience wrapper — summaries are just alerts with no photo."""
        return self.send_alert(message)

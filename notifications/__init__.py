"""
Notification package — lazy singleton factory.

Usage (anywhere in the project):
    from notifications import get_notifier
    get_notifier().send_alert("Critical threat on 10.0.0.1")
    result = get_notifier().request_authorization(None, timeout_sec=90)
"""

import json
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import Notifier

logger = logging.getLogger(__name__)

_notifier = None
_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "notifier.json")


def get_notifier() -> "Notifier":
    """Return the process-wide Notifier singleton, building it on first call."""
    global _notifier
    if _notifier is None:
        _notifier = _build()
    return _notifier


def _build() -> "Notifier":
    config = _load_config()
    backend = config.get("backend", "console").lower()

    if backend == "telegram":
        return _build_telegram(config.get("telegram", {}))

    if backend == "local_smtp":
        return _build_local_smtp(config.get("local_smtp", {}))

    if backend == "aegis":
        return _build_aegis(config.get("aegis", {}))

    # Fallback — safe for dev/test
    logger.warning("[Notifier] No backend configured — using ConsoleNotifier")
    from .console import ConsoleNotifier
    return ConsoleNotifier()


def _load_config() -> dict:
    path = os.path.normpath(_CONFIG_PATH)
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"[Notifier] Could not read {path}: {e}")
        return {}


def _build_telegram(cfg: dict) -> "Notifier":
    token = os.environ.get(cfg.get("bot_token_env", "TELEGRAM_BOT_TOKEN"), "").strip()
    chat_id = os.environ.get(cfg.get("chat_id_env", "TELEGRAM_CHAT_ID"), "").strip()

    if not token or not chat_id:
        logger.warning("[Notifier] Telegram token/chat_id missing — falling back to ConsoleNotifier")
        from .console import ConsoleNotifier
        return ConsoleNotifier()

    from .telegram import TelegramNotifier
    logger.info("[Notifier] TelegramNotifier active")
    return TelegramNotifier(token, chat_id)


def _build_local_smtp(cfg: dict) -> "Notifier":
    from .local_smtp import LocalSMTPNotifier
    logger.info(
        f"[Notifier] LocalSMTPNotifier active "
        f"(smtp={cfg.get('smtp_host','localhost')}:{cfg.get('smtp_port',25)} "
        f"imap={cfg.get('imap_host','localhost')}:{cfg.get('imap_port',993)})"
    )
    return LocalSMTPNotifier(cfg)


def _build_aegis(cfg: dict) -> "Notifier":
    # Placeholder until Phase 1 is built — falls back to Console
    # so the config can be set to "aegis" ahead of time without breaking anything.
    try:
        from .aegis import AegisNotifier
        logger.info("[Notifier] AegisNotifier active")
        return AegisNotifier(cfg)
    except ImportError:
        logger.warning("[Notifier] AegisNotifier not yet built — falling back to ConsoleNotifier")
        from .console import ConsoleNotifier
        return ConsoleNotifier()

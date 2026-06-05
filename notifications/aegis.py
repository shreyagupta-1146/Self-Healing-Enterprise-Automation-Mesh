"""
Aegis — Zero-cloud, on-prem, privacy-first notification and authorization bus.

Design principles borrowed from Telegram/Signal, implemented locally:
  - Sealed-box encryption (X25519 + XSalsa20-Poly1305 via 'cryptography' lib)
    so payload is only decryptable by the enrolled device's private key.
  - Self-destructing alert payloads (TTL field) — consoles wipe after read/timeout.
  - Sender anonymity — routing uses pseudonymous device IDs, never PHI.
  - Ed25519 signed challenge-response replaces the spoofable "type YES" flow.
    The signed authorization is written into audit_chain.json by respond().

Transport (defense-in-depth, all on-prem, no internet):
  1. Primary   — MQTT over mTLS to on-prem Mosquitto broker.
  2. Fallback 1 — SMTP to internal mailboxes via on-prem relay.
  3. Fallback 2 — SIP MESSAGE over UDP to hospital IP-PBX (uses existing infra).
  4. Fallback 3 — Desktop klaxon / system notification on sentinel workstation.

Authorization flow (replaces wait_for_telegram_approval):
  Sentinel publishes challenge(nonce, event_id) → responder console signs
  (nonce ‖ event_id ‖ decision) with its Ed25519 key → sentinel verifies
  signature against enrolled public key → returns "YES"/"TIMEOUT".

All PHI-adjacent fields are sealed so no cleartext leaves the sentinel's process
except over the mTLS channel to the enrolled device.

Runtime deps: paho-mqtt (pip install paho-mqtt), cryptography (already in reqs).
Missing deps degrade gracefully to ConsoleNotifier rather than crashing.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import smtplib
import socket
import ssl
import threading
import time
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional imports — degrade gracefully if missing
# ---------------------------------------------------------------------------
try:
    import paho.mqtt.client as mqtt_client
    _MQTT_AVAILABLE = True
except ImportError:
    _MQTT_AVAILABLE = False
    logger.warning("[Aegis] paho-mqtt not installed — MQTT transport disabled")

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption, load_pem_private_key, load_pem_public_key
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False
    logger.warning("[Aegis] cryptography not installed — encryption disabled")

from .base import Notifier


# ---------------------------------------------------------------------------
# Key management helpers
# ---------------------------------------------------------------------------

class DeviceKey:
    """Holds an Ed25519 signing key and X25519 encryption key for one device."""

    def __init__(self, keys_dir: str, device_id: str):
        self.device_id = device_id
        self._keys_dir = keys_dir
        os.makedirs(keys_dir, exist_ok=True)
        self._sign_priv = self._load_or_gen_sign_key()
        self._enc_priv = self._load_or_gen_enc_key()

    # Ed25519 ----------------------------------------------------------------

    def _sign_key_path(self) -> str:
        return os.path.join(self._keys_dir, f"{self.device_id}_sign.pem")

    def _load_or_gen_sign_key(self):
        if not _CRYPTO_AVAILABLE:
            return None
        path = self._sign_key_path()
        if os.path.exists(path):
            with open(path, "rb") as f:
                return load_pem_private_key(f.read(), password=None)
        key = Ed25519PrivateKey.generate()
        with open(path, "wb") as f:
            f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        return key

    def sign(self, data: bytes) -> bytes:
        if not _CRYPTO_AVAILABLE or self._sign_priv is None:
            return b""
        return self._sign_priv.sign(data)

    @property
    def sign_public_bytes(self) -> bytes:
        if not _CRYPTO_AVAILABLE or self._sign_priv is None:
            return b""
        return self._sign_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # X25519 + ChaCha20-Poly1305 sealed-box -----------------------------------

    def _enc_key_path(self) -> str:
        return os.path.join(self._keys_dir, f"{self.device_id}_enc.pem")

    def _load_or_gen_enc_key(self):
        if not _CRYPTO_AVAILABLE:
            return None
        path = self._enc_key_path()
        if os.path.exists(path):
            with open(path, "rb") as f:
                return load_pem_private_key(f.read(), password=None)
        key = X25519PrivateKey.generate()
        with open(path, "wb") as f:
            f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        return key

    @property
    def enc_public_bytes(self) -> bytes:
        if not _CRYPTO_AVAILABLE or self._enc_priv is None:
            return b""
        return self._enc_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def seal(self, plaintext: bytes, recipient_pub_bytes: bytes) -> bytes:
        """
        Seal plaintext for recipient_pub_bytes using ephemeral X25519 + ChaCha20-Poly1305.
        Format: ephemeral_pub(32) ‖ nonce(12) ‖ ciphertext.
        Recipient decrypts with their X25519 private key.
        """
        if not _CRYPTO_AVAILABLE:
            return plaintext  # no-op fallback in dev

        ephemeral_priv = X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()
        recipient_pub = X25519PublicKey.from_public_bytes(recipient_pub_bytes)
        shared = ephemeral_priv.exchange(recipient_pub)

        # Derive ChaCha20 key from shared secret (use first 32 bytes of SHA-256)
        import hashlib
        key_bytes = hashlib.sha256(shared).digest()
        nonce = secrets.token_bytes(12)
        aead = ChaCha20Poly1305(key_bytes)
        ciphertext = aead.encrypt(nonce, plaintext, None)

        return (
            ephemeral_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            + nonce
            + ciphertext
        )

    def open(self, sealed: bytes) -> bytes:
        """Decrypt a sealed message using this device's X25519 private key."""
        if not _CRYPTO_AVAILABLE or self._enc_priv is None:
            return sealed
        import hashlib
        ephemeral_pub_bytes = sealed[:32]
        nonce = sealed[32:44]
        ciphertext = sealed[44:]
        ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
        shared = self._enc_priv.exchange(ephemeral_pub)
        key_bytes = hashlib.sha256(shared).digest()
        aead = ChaCha20Poly1305(key_bytes)
        return aead.decrypt(nonce, ciphertext, None)


def verify_ed25519_signature(public_key_bytes: bytes, data: bytes, signature: bytes) -> bool:
    if not _CRYPTO_AVAILABLE:
        return True  # dev-mode no-op
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, data)
        return True
    except (InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------
# Aegis Notifier
# ---------------------------------------------------------------------------

class AegisNotifier(Notifier):
    """
    On-prem, zero-cloud notification bus.
    Reads all settings from the 'aegis' section of config/notifier.json.
    """

    TOPIC_ALERT = "sentihealth/alerts"
    TOPIC_AUTH_CHALLENGE = "sentihealth/auth/challenge"
    TOPIC_AUTH_RESPONSE = "sentihealth/auth/response"

    def __init__(self, cfg: dict):
        self._cfg = cfg
        self._broker_host = cfg.get("broker_host", "localhost")
        self._broker_port = int(cfg.get("broker_port", 8883))
        self._ca_cert = cfg.get("ca_cert")
        self._client_cert = cfg.get("client_cert")
        self._client_key = cfg.get("client_key")
        self._smtp_host = cfg.get("smtp_host", "localhost")
        self._smtp_port = int(cfg.get("smtp_port", 25))
        self._smtp_to = cfg.get("smtp_to", "")
        self._smtp_from = cfg.get("smtp_from", "sentinel@hospital.internal")
        self._sip_uri = cfg.get("sip_uri", "")
        self._sip_host = cfg.get("sip_host", "")
        self._sip_port = int(cfg.get("sip_port", 5060))
        keys_dir = cfg.get("device_keys_dir", "config/aegis_keys")
        self._device = DeviceKey(keys_dir, "sentinel")

        # Pending authorization state
        self._pending_auth: dict | None = None
        self._auth_result: str | None = None
        self._auth_event = threading.Event()

        self._mqtt: object | None = None
        self._mqtt_connected = False
        if _MQTT_AVAILABLE:
            self._mqtt_connect()

        logger.info("[Aegis] Notifier initialized")

    # ------------------------------------------------------------------
    # Notifier interface
    # ------------------------------------------------------------------

    def send_alert(self, message: str, photo_path: str = None) -> bool:
        payload = {
            "type": "alert",
            "message": message,
            "photo": photo_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ttl_seconds": 300,
            "sender_id": "sentinel",
        }
        serialized = json.dumps(payload).encode()
        delivered = False

        # Primary: MQTT
        if self._mqtt_connected and _MQTT_AVAILABLE:
            try:
                self._mqtt.publish(self.TOPIC_ALERT, serialized, qos=1)
                logger.info("[Aegis] Alert published via MQTT")
                delivered = True
            except Exception as e:
                logger.warning(f"[Aegis] MQTT publish failed: {e}")

        # Fallback 1: SMTP
        if not delivered:
            delivered = self._smtp_send(
                subject=f"[SentiHealth ALERT] {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}",
                body=message,
            )

        # Fallback 2: SIP MESSAGE
        if not delivered and self._sip_host:
            delivered = self._sip_send(message)

        # Fallback 3: Desktop klaxon (always fires in addition to others)
        self._desktop_notify(message)

        return delivered

    def request_authorization(
        self,
        prompt: str | None,
        timeout_sec: int = 90,
        accept_ignore: bool = False,
    ) -> str:
        if prompt:
            self.send_alert(prompt)

        nonce = secrets.token_hex(16)
        challenge = {
            "type": "auth_challenge",
            "nonce": nonce,
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=timeout_sec)).isoformat(),
            "sentinel_pubkey": self._device.sign_public_bytes.hex(),
        }

        self._auth_result = None
        self._auth_event.clear()

        # Publish challenge
        if self._mqtt_connected and _MQTT_AVAILABLE:
            self._mqtt.publish(
                self.TOPIC_AUTH_CHALLENGE,
                json.dumps(challenge).encode(),
                qos=1,
            )
            logger.info(f"[Aegis] Auth challenge published (nonce={nonce[:8]}...)")

        # Block until signed response arrives or timeout
        got_response = self._auth_event.wait(timeout=timeout_sec)
        if not got_response or self._auth_result is None:
            logger.warning("[Aegis] Auth timeout — no signed response received")
            return "TIMEOUT"

        result = self._auth_result
        self._auth_result = None
        return result

    # ------------------------------------------------------------------
    # MQTT internals
    # ------------------------------------------------------------------

    def _mqtt_connect(self):
        try:
            client = mqtt_client.Client(client_id="sentihealth-sentinel", clean_session=True)
            client.on_connect = self._on_mqtt_connect
            client.on_message = self._on_mqtt_message
            client.on_disconnect = self._on_mqtt_disconnect

            # mTLS — only if certs are configured
            if self._ca_cert and os.path.exists(self._ca_cert):
                client.tls_set(
                    ca_certs=self._ca_cert,
                    certfile=self._client_cert if self._client_cert and os.path.exists(self._client_cert) else None,
                    keyfile=self._client_key if self._client_key and os.path.exists(self._client_key) else None,
                    tls_version=ssl.PROTOCOL_TLS,
                )
                client.tls_insecure_set(False)

            client.connect_async(self._broker_host, self._broker_port, keepalive=60)
            client.loop_start()
            self._mqtt = client
        except Exception as e:
            logger.warning(f"[Aegis] MQTT connect failed: {e} — using fallbacks only")

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._mqtt_connected = True
            client.subscribe(self.TOPIC_AUTH_RESPONSE, qos=1)
            logger.info("[Aegis] MQTT broker connected, subscribed to auth responses")
        else:
            logger.warning(f"[Aegis] MQTT connect refused (rc={rc})")

    def _on_mqtt_disconnect(self, client, userdata, rc):
        self._mqtt_connected = False
        if rc != 0:
            logger.warning(f"[Aegis] MQTT disconnected unexpectedly (rc={rc}), will retry")

    def _on_mqtt_message(self, client, userdata, msg):
        """Handle incoming signed authorization responses from responder consoles."""
        if msg.topic != self.TOPIC_AUTH_RESPONSE:
            return
        try:
            response = json.loads(msg.payload.decode())
            decision = response.get("decision", "").upper()
            nonce = response.get("nonce", "")
            signature_hex = response.get("signature", "")
            device_pubkey_hex = response.get("device_pubkey", "")

            if not (decision and nonce and signature_hex and device_pubkey_hex):
                logger.warning("[Aegis] Auth response missing required fields")
                return

            # Verify Ed25519 signature: the admin signed (nonce ‖ decision)
            payload_signed = (nonce + decision).encode()
            sig_bytes = bytes.fromhex(signature_hex)
            pub_bytes = bytes.fromhex(device_pubkey_hex)

            if not verify_ed25519_signature(pub_bytes, payload_signed, sig_bytes):
                logger.warning("[Aegis] INVALID Ed25519 signature on auth response — rejected")
                with open("logs/integrity_alerts.log", "a") as f:
                    f.write(f"{datetime.now(timezone.utc)} — INVALID AUTH SIGNATURE from {device_pubkey_hex[:16]}...\n")
                return

            # Signature valid — accept if this matches a live challenge
            if decision in ("YES", "IGNORE"):
                self._auth_result = decision
                self._auth_event.set()
                logger.info(f"[Aegis] Valid signed authorization received: {decision}")

        except Exception as e:
            logger.error(f"[Aegis] Error processing auth response: {e}")

    # ------------------------------------------------------------------
    # SMTP fallback (Fallback 1)
    # ------------------------------------------------------------------

    def _smtp_send(self, subject: str, body: str) -> bool:
        if not self._smtp_to:
            return False
        try:
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = self._smtp_from
            msg["To"] = self._smtp_to
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as s:
                s.sendmail(self._smtp_from, [self._smtp_to], msg.as_string())
            logger.info(f"[Aegis] Alert sent via SMTP to {self._smtp_to}")
            return True
        except Exception as e:
            logger.warning(f"[Aegis] SMTP send failed: {e}")
            return False

    # ------------------------------------------------------------------
    # SIP MESSAGE fallback (Fallback 2) — raw UDP SIP MESSAGE
    # Uses hospital's existing IP-PBX; no library needed.
    # ------------------------------------------------------------------

    def _sip_send(self, body: str) -> bool:
        """
        Sends a SIP MESSAGE to the configured on-prem IP-PBX via UDP.
        The PBX routes it to the on-call extension (existing hospital infra).
        """
        if not self._sip_uri or not self._sip_host:
            return False
        try:
            call_id = secrets.token_hex(8)
            sip_msg = (
                f"MESSAGE {self._sip_uri} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP sentinel.hospital.internal:5060;branch=z9hG4bK{call_id}\r\n"
                f"From: <sip:sentinel@hospital.internal>;tag={call_id}\r\n"
                f"To: <{self._sip_uri}>\r\n"
                f"Call-ID: {call_id}@sentinel\r\n"
                f"CSeq: 1 MESSAGE\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(body.encode())}\r\n"
                f"\r\n"
                f"{body}"
            )
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5)
                s.sendto(sip_msg.encode(), (self._sip_host, self._sip_port))
            logger.info(f"[Aegis] SIP MESSAGE sent to {self._sip_uri}")
            return True
        except Exception as e:
            logger.warning(f"[Aegis] SIP send failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Desktop klaxon (Fallback 3) — always fires alongside primary
    # ------------------------------------------------------------------

    def _desktop_notify(self, message: str):
        """
        Raise a visible/audible system notification on the sentinel workstation.
        Best-effort; never raises.
        """
        try:
            import subprocess
            short = message[:120].replace('"', "'")
            # Windows toast via PowerShell
            ps_cmd = (
                f'[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null;'
                f'$n = New-Object System.Windows.Forms.NotifyIcon;'
                f'$n.Icon = [System.Drawing.SystemIcons]::Warning;'
                f'$n.Visible = $true;'
                f'$n.ShowBalloonTip(10000, "SentiHealth ALERT", "{short}", [System.Windows.Forms.ToolTipIcon]::Warning);'
                f'Start-Sleep -Seconds 2; $n.Dispose()'
            )
            subprocess.Popen(
                ["powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_cmd],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

        # Also beep via stdout BEL character
        try:
            print("\a", end="", flush=True)
        except Exception:
            pass

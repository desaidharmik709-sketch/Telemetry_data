import selectors
from selectors import SelectorKey

# Workaround for selectors.py raising ValueError instead of KeyError on Python 3.12+ (e.g. invalid file descriptors)
# We apply the patch to both BaseSelector and _BaseSelectorImpl to handle subclasses overriding unregister.
for selector_cls in [selectors.BaseSelector, getattr(selectors, "_BaseSelectorImpl", None)]:
    if selector_cls is not None and hasattr(selector_cls, "unregister"):
        _orig_unregister = selector_cls.unregister
        def make_safe_unregister(orig_unreg):
            def _safe_unregister(self, fileobj):
                try:
                    return orig_unreg(self, fileobj)
                except (ValueError, KeyError):
                    # If it failed (e.g., closed socket with fd=-1), search for it by object identity in registered keys
                    found_fd = None
                    if hasattr(self, "_fd_to_key"):
                        for fd, key in list(self._fd_to_key.items()):
                            if key.fileobj is fileobj:
                                found_fd = fd
                                break
                    if found_fd is not None:
                        try:
                            return orig_unreg(self, found_fd)
                        except (ValueError, KeyError):
                            pass
                    # Fallback if not found: return a dummy SelectorKey to prevent unhandled KeyError crashes in kafka-python
                    return SelectorKey(fileobj, -1, 0, None)
            return _safe_unregister
        selector_cls.unregister = make_safe_unregister(_orig_unregister)

import json
import time
from pathlib import Path
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

OUTPUT_DIR = Path("compliance_output")


def normalize_stdout(stdout):

    if stdout is None:
        return []

    if isinstance(stdout, list):
        return stdout

    if isinstance(stdout, dict):
        return [stdout]

    if isinstance(stdout, str):
        return [{
            "raw_output": stdout
        }]

    return []


for file in sorted(OUTPUT_DIR.glob("*.json")):

    try:

        with open(file, "r", encoding="utf-8") as f:
            content = json.load(f)

        if not isinstance(content, list):
            content = [content]

        for obj in content:

            fingerprint = obj.get(
                "device_fingerprint",
                {}
            )

            payload_message = obj.get(
                "payload_message",
                {}
            )

            collection_metadata = payload_message.get(
                "collection_metadata",
                {}
            )

            telemetry = payload_message.get(
                "data",
                {}
            )

            username = collection_metadata.get(
                "username",
                "unknown"
            )

            hostname = fingerprint.get(
                "device_name",
                "unknown"
            )

            timestamp = obj.get(
                "timestamp",
                ""
            )

            stdout = telemetry.get(
                "stdout",
                []
            )

            normalized_records = normalize_stdout(stdout)

            if not normalized_records:

                normalized_records = [{
                    "message": "No stdout records"
                }]

            total = len(normalized_records)

            for idx, record in enumerate(
                normalized_records,
                start=1
            ):

                kafka_payload = {
                    "file_name": file.name,
                    "event_id": obj.get("event_id", ""),
                    "event_type": obj.get("event_type", ""),
                    "severity": obj.get("severity", "INFO"),
                    "timestamp": timestamp,
                    "username": username,
                    "hostname": hostname,
                    "device_fingerprint": fingerprint,
                    "record": record
                }

                producer.send(
                    "compliance-data",
                    value=kafka_payload
                )

                print(
                    f"[SENT] "
                    f"{file.name} "
                    f"{idx}/{total}"
                )

                producer.flush()

                time.sleep(0.03)
    except Exception as e:

        print(
            f"[ERROR] "
            f"{file.name}: {e}"
        )

print("\nALL LOGS SENT")

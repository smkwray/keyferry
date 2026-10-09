import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("capture_status", ROOT / "scripts/capture_local_status.py")
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
DEVICE = "11111111-1111-4111-8111-111111111111"


class CaptureStatusTests(unittest.TestCase):
    def test_valid_typed_metadata_and_registered_reason(self):
        import json
        document = {"schema": "keyferry.local-status.v1", "device_id": DEVICE.replace("-", ""),
                    "device": {"release": "0.2.0-fi"}, "safety": {}, "network": {}, "ble_hid": {},
                    "policy": {}, "last_receipt": None,
                    "wifi_diagnostic": {"last_wifi_reject_reason": "wifi_preference_expired", "elapsed_to_close_ms": 15000}}
        raw = json.dumps(document).encode()
        self.assertEqual(capture.status_document(raw, DEVICE)["wifi_diagnostic"]["elapsed_to_close_ms"], 15000)

    def test_wrong_device_duplicate_unknown_and_secret_strings_cannot_be_retained(self):
        import json
        document = {"schema": "keyferry.local-status.v1", "device_id": DEVICE.replace("-", ""),
                    "device": {}, "safety": {}, "network": {}, "ble_hid": {}, "policy": {},
                    "last_receipt": None, "wifi_diagnostic": None}
        for change in [{"device_id": "00" * 16}, {"payload": "private"},
                       {"network": {"wifi_password": "private"}},
                       {"wifi_diagnostic": {"last_wifi_reject_reason": "private"}}]:
            with self.assertRaises(ValueError):
                capture.status_document(json.dumps({**document, **change}).encode(), DEVICE)
        with self.assertRaises(ValueError):
            capture.status_document(json.dumps({key: value for key, value in document.items() if key != "network"}).encode(), DEVICE)
        with self.assertRaises(ValueError):
            capture.status_document(b'{"schema":1,"schema":2}', DEVICE)
        with self.assertRaises(ValueError):
            capture.status_document(b" " * 16385, DEVICE)


if __name__ == "__main__":
    unittest.main()

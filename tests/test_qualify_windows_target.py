import json
import os
from pathlib import Path
import unittest
import uuid

from scripts.qualify_windows_target import CHECKS, assess, build_sequence, glide, hidden_run, local_usb_matches


class WindowsTargetTests(unittest.TestCase):
    def test_exact_present_composite_identity_only(self):
        device = str(uuid.UUID(int=1 << 64))
        parent = {'instance_id': 'USB\\VID_303A&PID_4008\\'+uuid.UUID(device).hex[:31],
                  'service': 'usbccgp'}
        self.assertTrue(local_usb_matches(device, [parent]))
        for field, value in [('instance_id', parent['instance_id'].replace('303A', '1234')),
                             ('instance_id', parent['instance_id'].replace('PID_4008', 'PID_4008&MI_02')),
                             ('service', 'HidUsb'), ('instance_id', parent['instance_id']+'0')]:
            self.assertFalse(local_usb_matches(device, [dict(parent, **{field: value})]))
        self.assertFalse(local_usb_matches(device, []))
        self.assertFalse(local_usb_matches(str(uuid.UUID(int=2 << 64)), [parent]))

    def test_glide_starts_at_current_pixel_and_eases(self):
        actions = glide((0.1, 0.2), (0.8, 0.7))
        moves = actions[::2]
        self.assertEqual((moves[0]['x'], moves[0]['y']), (0.1, 0.2))
        self.assertEqual((moves[-1]['x'], moves[-1]['y']), (0.8, 0.7))
        deltas = [b['x']-a['x'] for a, b in zip(moves, moves[1:])]
        self.assertTrue(all(d >= 0 for d in deltas))
        self.assertLess(deltas[0], deltas[9])
        self.assertLess(deltas[-1], deltas[9])

    def test_sequences_validate_with_production_keyctl(self):
        keyctl = os.environ.get('KEYFERRY_KEYCTL', str(Path(__file__).resolve().parents[1]/'target'/'debug'/'keyctl.exe'))
        self.assertTrue(Path(keyctl).is_file(), 'Build keyctl or set KEYFERRY_KEYCTL to the tested executable')
        for check in CHECKS:
            with self.subTest(check=check):
                body = build_sequence(check, (0.3, 0.4))
                self.assertEqual('keyboard_profile' in body, check == 'typing')
                result = hidden_run([keyctl, 'input-sequence', '--validate'], input=json.dumps(body))
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertTrue(json.loads(result.stdout)['valid'])

    def test_measurements_reject_jump_and_unobserved_input(self):
        emitted = {'outcome': 'EMITTED'}
        result = assess('glide', (0, 0), (300, 400), [], emitted, (1001, 1001))
        self.assertFalse(result['passed'])
        self.assertFalse(assess('left_click', (20, 30), (20, 30), [], emitted, (1001, 1001))['passed'])
        self.assertTrue(assess('relative', (20, 30), (20, 30), [], {'outcome': 'REJECTED', 'error': {'code': 'input.capability_required'}}, (1001, 1001))['passed'])
        self.assertFalse(assess('relative', (20, 30), (20, 30), [], {'outcome': 'REJECTED', 'error': {'code': 'daemon.unavailable'}}, (1001, 1001))['passed'])
        self.assertFalse(assess('relative', (20, 30), (20, 30), [], {'outcome': 'UNKNOWN'}, (1001, 1001))['passed'])
        self.assertFalse(assess('relative', (20, 30), (21, 30), [], emitted, (1001, 1001))['passed'])
        self.assertTrue(assess('relative', (20, 30), (80, 30), [], emitted, (1001, 1001))['passed'])  # moved and stayed
        self.assertFalse(assess('relative', (20, 30), (20, 30), [], emitted, (1001, 1001))['passed'])  # snapped back
        events = [dict(kind='key', char=c) for c in 'abc']
        self.assertTrue(assess('typing', (0, 0), (0, 0), events, emitted, (1001, 1001))['passed'])
        self.assertFalse(assess('typing', (0, 0), (0, 0), events[:2], emitted, (1001, 1001))['passed'])


if __name__ == '__main__':
    unittest.main()

"""Qualify Windows-delivered HID input on this computer only; JSON stdout, no frames.

Use a stick physically plugged into this Windows computer. Keep hands off input
until the fullscreen receiver closes; Escape aborts. Never retries a command.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid

CHECKS = ('glide', 'left_click', 'right_click', 'wheel', 'relative', 'drag', 'typing')


def hidden_run(command, **kwargs):
    # Same CREATE_NO_WINDOW policy as keyferry_core::process and the existing probes.
    return subprocess.run(command, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                          capture_output=True, text=True, timeout=45, **kwargs)


def local_usb_matches(device, instances):
    serial = uuid.UUID(device).hex.upper()
    return any(re.fullmatch(r'USB\\VID_303A&PID_[0-9A-F]{4}\\' + serial,
                            item['instance_id'].upper())
               and item['service'].lower() == 'usbccgp' for item in instances)


def require_local_usb(device):
    # Only present composite parents, not cached/remote HID children. UUID never enters shell code.
    command = r"""$ErrorActionPreference='Stop'; $items=@(Get-PnpDevice -PresentOnly -Class USB | Where-Object { $_.InstanceId -like 'USB\VID_303A&PID_*' } | ForEach-Object { $service=(Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_Service -ErrorAction Stop).Data; @{instance_id=$_.InstanceId;service=$service} }); ConvertTo-Json -InputObject $items -Compress"""
    result = hidden_run(['pwsh', '-NoProfile', '-NonInteractive', '-Command', command])
    if result.returncode or not local_usb_matches(device, json.loads(result.stdout)):
        raise RuntimeError('local_usb_required: exact VID 303A composite serial is not present on this computer')


def sequence(actions):
    body = dict(schema='keyferry.input-sequence.v2', arm='command-scoped',
                start_within_ms=5000, actions=actions)
    if any(a['type'] in ('text', 'tap', 'chord') for a in actions):
        body['keyboard_profile'] = 'windows-us'
    return body


def glide(start, end, steps=20):
    actions = []
    # Establish the current position, never a guessed origin. HID endpoints map to W-1/H-1.
    for i in range(steps + 1):
        t = i / steps
        eased = t * t * (3 - 2 * t)
        actions += [dict(type='move_absolute', x=round(start[0] + (end[0]-start[0])*eased, 6),
                         y=round(start[1] + (end[1]-start[1])*eased, 6)),
                    dict(type='wait', ms=10)]
    return actions


def build_sequence(check, start):
    if check == 'glide':
        actions = glide(start, (0.30, 0.40))
    elif check == 'drag':
        # 8 glide reports plus balanced edges fit the 470ms held-span/report budget.
        actions = [dict(type='move_absolute', x=start[0], y=start[1]),
                   dict(type='button_down', button='button_1'), dict(type='wait', ms=40)]
        actions += glide(start, (0.55, 0.60), 8)[2:]
        actions += [dict(type='wait', ms=30), dict(type='button_up', button='button_1')]
    elif check in ('left_click', 'right_click'):
        actions = [dict(type='move_absolute', x=start[0], y=start[1]),
                   dict(type='click', button='button_1' if check == 'left_click' else 'button_2')]
    elif check == 'wheel':
        actions = [dict(type='move_absolute', x=start[0], y=start[1]),
                   dict(type='scroll', vertical=-3, horizontal=0)]
    elif check == 'relative':
        actions = [dict(type='move_relative', dx_counts=60, dy_counts=0)]
    elif check == 'typing':
        actions = [dict(type='text', value='abc')]
    else:
        raise ValueError('unknown check')
    return sequence(actions)


def assess(check, before, after, events, command, size):
    emitted = command.get('outcome') == 'EMITTED'
    close = lambda a, b: max(abs(a[i] - b[i]) for i in (0, 1)) <= 5
    target = (round(0.30*(size[0]-1)), round(0.40*(size[1]-1))) if check == 'glide' else (
        round(0.55*(size[0]-1)), round(0.60*(size[1]-1)))
    kinds = [e['kind'] for e in events]
    passed = False
    if check == 'glide':
        moves = [before] + [e['position'] for e in events if e['kind'] == 'move'] + [after]
        # Large discontinuities or backtracking fail even if the final pixel is correct.
        distance = sum((target[i]-before[i])**2 for i in (0, 1))**0.5
        smooth = all(sum((b[i]-a[i])**2 for i in (0, 1))**0.5 <= max(8, distance*0.20)
                     for a, b in zip(moves, moves[1:]))
        progress = lambda p: sum((p[i]-before[i])*(target[i]-before[i]) for i in (0, 1))
        smooth &= all(progress(b) >= progress(a)-distance*5 for a, b in zip(moves, moves[1:]))
        passed = emitted and close(after, target) and smooth
    elif check in ('left_click', 'right_click', 'drag'):
        button = 3 if check == 'right_click' else 1
        down, up = f'down{button}', f'up{button}'
        balanced = down in kinds and up in kinds and kinds.index(down) < kinds.index(up)
        if balanced:
            edges = [e for e in events if e['kind'] in (down, up)]
            balanced = len(edges) == 2 and close(edges[0]['position'], before)
            if check == 'drag':
                held = edges[1]['time']-edges[0]['time']
                balanced &= held <= 0.470 and close(edges[1]['position'], target)
                balanced &= any(e['kind'] == 'drag1' for e in events)
            else:
                balanced &= close(edges[1]['position'], before)
        passed = emitted and balanced and close(after, target if check == 'drag' else before)
    elif check == 'wheel':
        passed = emitted and sum(e.get('delta', 0) for e in events if e['kind'] == 'wheel') == -360 and close(after, before)
    elif check == 'relative':
        accepted = emitted or (command.get('outcome') == 'REJECTED' and
                               (command.get('error') or {}).get('code') == 'input.capability_required')
        passed = accepted and after == before
        passed &= all(e['position'] == before for e in events if e['kind'] in ('move', 'drag1'))
    elif check == 'typing':
        passed = emitted and ''.join(e.get('char', '') for e in events if e['kind'] == 'key') == 'abc'
    return dict(check=check, passed=bool(passed), before=before, after=after,
                expected=target if check in ('glide', 'drag') else before,
                command=command, events=events)


def qualify(device, checks, keyctl):
    import tkinter as tk
    user = ctypes.windll.user32
    user.SetProcessDPIAware()
    size = (user.GetSystemMetrics(0), user.GetSystemMetrics(1))
    class Point(ctypes.Structure):
        _fields_ = [('x', ctypes.c_long), ('y', ctypes.c_long)]
    def cursor():
        p = Point()
        if not user.GetCursorPos(ctypes.byref(p)):
            raise RuntimeError('cursor_unavailable')
        return (p.x, p.y)
    events, results = [], []
    abort = threading.Event()
    root = tk.Tk()
    root.attributes('-fullscreen', True)
    root.attributes('-topmost', True)
    root.configure(bg='#203040')
    tk.Label(root, text='Windows HID qualification — keep hands off input; Escape aborts',
             bg='#203040', fg='white', font=('Segoe UI', 20)).pack(pady=40)
    for binding, kind in (('<Motion>', 'move'), ('<B1-Motion>', 'drag1'),
                          ('<ButtonPress-1>', 'down1'), ('<ButtonRelease-1>', 'up1'),
                          ('<ButtonPress-3>', 'down3'), ('<ButtonRelease-3>', 'up3'),
                          ('<MouseWheel>', 'wheel'), ('<KeyPress>', 'key')):
        def record(e, kind=kind):
            events.append(dict(time=time.monotonic(), kind=kind, position=(e.x_root, e.y_root),
                               delta=getattr(e, 'delta', 0), char=getattr(e, 'char', '')))
        root.bind(binding, record)
    root.bind('<Escape>', lambda _: abort.set())
    root.protocol('WM_DELETE_WINDOW', abort.set)
    root.focus_force()
    done = threading.Event()
    def run():
        try:
            time.sleep(1)
            for check in checks:
                if abort.is_set():
                    raise RuntimeError('aborted')
                require_local_usb(device)  # Recheck at every command; never use a remote target.
                before = cursor()
                if not (0 <= before[0] < size[0] and 0 <= before[1] < size[1]):
                    raise RuntimeError('cursor_must_be_on_primary_display')
                start = (before[0]/(size[0]-1), before[1]/(size[1]-1))
                body = json.dumps(build_sequence(check, start))
                validation = hidden_run([keyctl, 'input-sequence', '--validate'], input=body)
                if validation.returncode or not json.loads(validation.stdout).get('valid'):
                    raise RuntimeError('sequence_validation_failed')
                require_local_usb(device)
                if abort.is_set():
                    raise RuntimeError('aborted')
                begin = len(events)
                # No replay on error/UNKNOWN. stdin stays memory-only.
                output = hidden_run([keyctl, 'input-sequence', device], input=body)
                command = json.loads(output.stdout.strip().splitlines()[-1])
                time.sleep(0.35)
                result = assess(check, before, cursor(), events[begin:], command, size)
                results.append(result)
                if command.get('outcome') not in ('EMITTED', 'REJECTED'):
                    raise RuntimeError('uncertain_command_stop')
        except Exception as error:
            results.append(dict(check='execution', passed=False, error=str(error)))
        finally:
            done.set()
    def poll():
        if done.is_set():
            root.destroy()
        else:
            root.after(50, poll)
    worker = threading.Thread(target=run)
    worker.start()
    root.after(50, poll)
    root.mainloop()
    worker.join()
    return dict(schema='keyferry.windows-target-qualification.v1', device=device,
                screen=size, passed=all(r['passed'] for r in results), checks=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', required=True, type=lambda value: str(uuid.UUID(value)))
    parser.add_argument('--checks', nargs='+', choices=CHECKS, default=list(CHECKS))
    parser.add_argument('--keyctl', default=os.environ.get('KEYFERRY_KEYCTL', str(
        Path(os.environ.get('LOCALAPPDATA', ''))/'Programs'/'Keyferry'/'keyctl.exe')))
    args = parser.parse_args()
    try:
        if os.name != 'nt':
            raise RuntimeError('windows_required')
        require_local_usb(args.device)
        # Authenticated and disarmed before sending; USB presence alone is insufficient.
        output = hidden_run([args.keyctl, 'devices'])
        inventory = json.loads(output.stdout)
        devices = inventory if isinstance(inventory, list) else inventory['devices']
        device = next(d for d in devices if d['id'] == args.device)
        if output.returncode or device.get('link') != 'authenticated' or device.get('armed') is not False:
            raise RuntimeError('authenticated_disarmed_device_required')
        result = qualify(args.device, args.checks, args.keyctl)
    except Exception as error:
        result = dict(passed=False, error=str(error))
    print(json.dumps(result))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()

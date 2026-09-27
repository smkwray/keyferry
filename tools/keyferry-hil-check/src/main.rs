#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AEvent {
    Down,
    Up,
}

#[cfg(any(windows, test))]
fn verify_key_tap(events: &[AEvent]) -> Result<(), &'static str> {
    match events {
        [AEvent::Down, AEvent::Up] => Ok(()),
        [] => Err("no matching key report was observed from the ESP HID device"),
        [AEvent::Down] => Err("the key was pressed but no release was observed"),
        [AEvent::Up, ..] => Err("a key release arrived before its press"),
        _ => Err("the key repeated or produced more than one down/up pair"),
    }
}

#[cfg(any(windows, test))]
fn verify_two_key_chord(events: &[(u16, AEvent)], expected: [u16; 2]) -> Result<(), &'static str> {
    let mut down = [false; 2];
    let mut overlapped = false;
    for (vkey, event) in events {
        let index = expected
            .iter()
            .position(|candidate| candidate == vkey)
            .ok_or("an unexpected key was captured")?;
        match event {
            AEvent::Down if down[index] => return Err("a chord key repeated before release"),
            AEvent::Down => {
                down[index] = true;
                overlapped |= down.iter().all(|pressed| *pressed);
            }
            AEvent::Up if !down[index] => return Err("a chord key was released before its press"),
            AEvent::Up => down[index] = false,
        }
    }
    if events.is_empty() {
        return Err("no matching chord report was observed from the ESP HID device");
    }
    if down.iter().any(|pressed| *pressed) {
        return Err("a chord key was pressed but not released");
    }
    if !overlapped {
        return Err("the two chord keys did not overlap");
    }
    if events.len() != 4 {
        return Err("the chord produced duplicate key transitions");
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn esp_vid_pid(path: &str) -> Option<String> {
    let upper = path.to_ascii_uppercase();
    let start = upper.find("VID_303A&PID_")?;
    let end = start + "VID_303A&PID_".len() + 4;
    let token = upper.get(start..end)?;
    token[token.len() - 4..]
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then(|| token.to_owned())
}

#[cfg(any(windows, test))]
fn descriptor_line(
    identity: &str,
    usage_page: u16,
    usage: u16,
    input_bytes: u16,
    output_bytes: u16,
    feature_bytes: u16,
    ranges: &str,
) -> String {
    format!(
        "ESP HID descriptor: {identity}; top_usage_page=0x{usage_page:04X}; top_usage=0x{usage:04X}; input_report_bytes={input_bytes}; output_report_bytes={output_bytes}; feature_report_bytes={feature_bytes}; input_button_caps=[{ranges}]"
    )
}

#[cfg(windows)]
mod windows_capture {
    use super::{descriptor_line, esp_vid_pid, verify_key_tap, verify_two_key_chord, AEvent};
    use std::{
        ffi::c_void,
        mem::size_of,
        ptr, thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Devices::HumanInterfaceDevice::{
            HidD_FreePreparsedData, HidD_GetPreparsedData, HidP_GetButtonCaps, HidP_GetCaps,
            HidP_Input, HIDP_BUTTON_CAPS, HIDP_CAPS, HIDP_STATUS_SUCCESS,
        },
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        UI::{
            Input::{
                GetRawInputData, GetRawInputDeviceInfoW, GetRawInputDeviceList,
                RegisterRawInputDevices, RAWINPUT, RAWINPUTDEVICE, RAWINPUTDEVICELIST,
                RAWINPUTHEADER, RIDEV_DEVNOTIFY, RIDEV_INPUTSINK, RIDI_DEVICENAME, RID_INPUT,
                RIM_TYPEKEYBOARD,
            },
            WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, PeekMessageW,
                TranslateMessage, HWND_MESSAGE, MSG, PM_REMOVE, RI_KEY_BREAK, WM_INPUT,
            },
        },
    };

    const ERROR_U32: u32 = u32::MAX;
    const QUIET_AFTER_UP: Duration = Duration::from_millis(500);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CaptureMode {
        One(u16),
        Chord(u16, u16),
        Quiet,
    }

    pub fn run(args: &[String]) -> Result<(), String> {
        let (mode, timeout) = parse_request(args)?;
        let candidates = esp_keyboards()?;
        if args.first().map(String::as_str) == Some("list") {
            if candidates.is_empty() {
                println!("No ESP32 HID keyboard is present.");
            } else {
                for (_, identity, _) in &candidates {
                    println!("ESP HID keyboard: {identity}");
                }
            }
            return Ok(());
        }
        if candidates.len() != 1 {
            return Err(format!(
                "expected exactly one ESP32 HID keyboard, found {}",
                candidates.len()
            ));
        }
        let (device, identity, path) = &candidates[0];
        if args.first().map(String::as_str) == Some("describe") {
            return describe(path, identity);
        }
        match mode {
            CaptureMode::One(vkey) => {
                println!("Capturing {identity}; send exactly one matching key tap now.");
                capture(*device, timeout, mode)?;
                println!(
                    "PASS: one virtual-key 0x{vkey:02X} down/up from {identity}; no repeat observed for 500 ms."
                );
            }
            CaptureMode::Chord(first, second) => {
                println!("Capturing {identity}; send exactly one matching two-key chord now.");
                capture(*device, timeout, mode)?;
                println!(
                    "PASS: virtual keys 0x{first:02X} and 0x{second:02X} overlapped and released once from {identity}."
                );
            }
            CaptureMode::Quiet => {
                println!("Monitoring {identity}; no key event is permitted.");
                capture(*device, timeout, mode)?;
                println!("PASS: no OS-level key event from {identity} during the observation.");
            }
        }
        Ok(())
    }

    fn parse_request(args: &[String]) -> Result<(CaptureMode, Duration), String> {
        match args.first().map(String::as_str) {
            Some("list") if args.len() == 1 => Ok((CaptureMode::Quiet, Duration::from_secs(10))),
            Some("describe") if args.len() == 1 => {
                Ok((CaptureMode::Quiet, Duration::from_secs(10)))
            }
            Some("capture") => Ok((CaptureMode::One(0x41), parse_timeout(args, 1)?)),
            Some("capture-vkey") => {
                let vkey = parse_vkey(args.get(1))?;
                Ok((CaptureMode::One(vkey), parse_timeout(args, 2)?))
            }
            Some("capture-chord") => {
                let first = parse_vkey(args.get(1))?;
                let second = parse_vkey(args.get(2))?;
                if first == second {
                    return Err("chord virtual keys must be distinct".to_owned());
                }
                Ok((CaptureMode::Chord(first, second), parse_timeout(args, 3)?))
            }
            Some("quiet") => Ok((CaptureMode::Quiet, parse_timeout(args, 1)?)),
            _ => Err(usage()),
        }
    }

    fn usage() -> String {
        "use `keyferry-hil-check list`, `keyferry-hil-check describe`, `keyferry-hil-check capture [--timeout-ms N]`, `keyferry-hil-check capture-vkey HEX [--timeout-ms N]`, `keyferry-hil-check capture-chord HEX HEX [--timeout-ms N]`, or `keyferry-hil-check quiet [--timeout-ms N]`"
            .to_owned()
    }

    fn parse_vkey(raw: Option<&String>) -> Result<u16, String> {
        let raw = raw.ok_or_else(usage)?;
        let raw = raw.strip_prefix("0x").unwrap_or(raw);
        u16::from_str_radix(raw, 16)
            .ok()
            .filter(|value| *value > 0 && *value <= 0xff)
            .ok_or_else(|| "virtual key must be hexadecimal from 01 through FF".to_owned())
    }

    fn parse_timeout(args: &[String], start: usize) -> Result<Duration, String> {
        match args.get(start).map(String::as_str) {
            None => Ok(Duration::from_secs(10)),
            Some("--timeout-ms") if args.len() == start + 2 => {
                let value = args[start + 1]
                    .parse::<u64>()
                    .ok()
                    .filter(|value| (1_000..=60_000).contains(value))
                    .ok_or_else(|| "timeout must be from 1000 through 60000 ms".to_owned())?;
                Ok(Duration::from_millis(value))
            }
            _ => Err("capture modes accept only optional `--timeout-ms N`".to_owned()),
        }
    }

    fn esp_keyboards() -> Result<Vec<(HANDLE, String, String)>, String> {
        unsafe {
            let mut count = 0_u32;
            if GetRawInputDeviceList(
                ptr::null_mut(),
                &mut count,
                size_of::<RAWINPUTDEVICELIST>() as u32,
            ) == ERROR_U32
            {
                return Err("Windows could not enumerate raw-input devices".to_owned());
            }
            let mut devices = vec![RAWINPUTDEVICELIST::default(); count as usize];
            let actual = GetRawInputDeviceList(
                devices.as_mut_ptr(),
                &mut count,
                size_of::<RAWINPUTDEVICELIST>() as u32,
            );
            if actual == ERROR_U32 {
                return Err("Windows could not read raw-input devices".to_owned());
            }
            let mut result = Vec::new();
            for device in devices.into_iter().take(actual as usize) {
                if device.dwType != RIM_TYPEKEYBOARD {
                    continue;
                }
                let path = device_name(device.hDevice)?;
                if let Some(identity) = esp_vid_pid(&path) {
                    result.push((device.hDevice, identity, path));
                }
            }
            Ok(result)
        }
    }

    unsafe fn device_name(device: HANDLE) -> Result<String, String> {
        let mut length = 0_u32;
        if unsafe { GetRawInputDeviceInfoW(device, RIDI_DEVICENAME, ptr::null_mut(), &mut length) }
            == ERROR_U32
        {
            return Err("Windows could not size a raw-input device name".to_owned());
        }
        let mut buffer = vec![0_u16; length as usize + 1];
        let actual = unsafe {
            GetRawInputDeviceInfoW(
                device,
                RIDI_DEVICENAME,
                buffer.as_mut_ptr().cast::<c_void>(),
                &mut length,
            )
        };
        if actual == ERROR_U32 {
            return Err("Windows could not read a raw-input device name".to_owned());
        }
        Ok(String::from_utf16_lossy(&buffer[..actual as usize]))
    }

    fn describe(path: &str, identity: &str) -> Result<(), String> {
        unsafe {
            let mut path_wide = path.encode_utf16().collect::<Vec<_>>();
            path_wide.push(0);
            let handle = CreateFileW(
                path_wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err("Windows could not open the ESP HID descriptor".to_owned());
            }
            let result = describe_open_handle(handle, identity);
            CloseHandle(handle);
            result
        }
    }

    unsafe fn describe_open_handle(handle: HANDLE, identity: &str) -> Result<(), String> {
        let mut preparsed = 0;
        if !unsafe { HidD_GetPreparsedData(handle, &mut preparsed) } {
            return Err("Windows could not read the ESP HID preparsed descriptor".to_owned());
        }
        let result = (|| {
            let mut caps = HIDP_CAPS::default();
            if unsafe { HidP_GetCaps(preparsed, &mut caps) } != HIDP_STATUS_SUCCESS {
                return Err("Windows could not parse the ESP HID capabilities".to_owned());
            }
            let mut button_caps =
                vec![HIDP_BUTTON_CAPS::default(); usize::from(caps.NumberInputButtonCaps)];
            let mut button_count = caps.NumberInputButtonCaps;
            if button_count > 0
                && unsafe {
                    HidP_GetButtonCaps(
                        HidP_Input,
                        button_caps.as_mut_ptr(),
                        &mut button_count,
                        preparsed,
                    )
                } != HIDP_STATUS_SUCCESS
            {
                return Err("Windows could not parse the ESP HID input usages".to_owned());
            }
            let ranges = button_caps
                .iter()
                .take(usize::from(button_count))
                .map(|cap| {
                    let (minimum, maximum) = if cap.IsRange {
                        let range = unsafe { cap.Anonymous.Range };
                        (range.UsageMin, range.UsageMax)
                    } else {
                        let item = unsafe { cap.Anonymous.NotRange };
                        (item.Usage, item.Usage)
                    };
                    format!(
                        "page=0x{:04X},usage=0x{minimum:04X}..0x{maximum:04X},report_id={},report_count={}",
                        cap.UsagePage, cap.ReportID, cap.ReportCount
                    )
                })
                .collect::<Vec<_>>()
                .join(";");
            println!(
                "{}",
                descriptor_line(
                    identity,
                    caps.UsagePage,
                    caps.Usage,
                    caps.InputReportByteLength,
                    caps.OutputReportByteLength,
                    caps.FeatureReportByteLength,
                    &ranges,
                )
            );
            Ok(())
        })();
        unsafe { HidD_FreePreparsedData(preparsed) };
        result
    }

    fn capture(device: HANDLE, timeout: Duration, mode: CaptureMode) -> Result<(), String> {
        unsafe {
            let class = "STATIC\0".encode_utf16().collect::<Vec<_>>();
            let title = "keyferry-hil-check\0".encode_utf16().collect::<Vec<_>>();
            let window = CreateWindowExW(
                0,
                class.as_ptr(),
                title.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            );
            if window.is_null() {
                return Err("Windows could not create the raw-input capture window".to_owned());
            }
            let registration = RAWINPUTDEVICE {
                usUsagePage: 0x01,
                usUsage: 0x06,
                dwFlags: RIDEV_INPUTSINK | RIDEV_DEVNOTIFY,
                hwndTarget: window,
            };
            if RegisterRawInputDevices(&registration, 1, size_of::<RAWINPUTDEVICE>() as u32) == 0 {
                DestroyWindow(window);
                return Err("Windows rejected raw keyboard capture registration".to_owned());
            }

            let started = Instant::now();
            let mut up_at = None;
            let mut events = Vec::new();
            let mut chord_events = Vec::new();
            let mut message = MSG::default();
            while started.elapsed() < timeout {
                while PeekMessageW(&mut message, window, 0, 0, PM_REMOVE) != 0 {
                    if message.message == WM_INPUT {
                        if let Some((vkey, event)) = read_key_event(message.lParam, device)? {
                            if mode == CaptureMode::Quiet {
                                DestroyWindow(window);
                                return Err(format!(
                                    "unexpected {} event for virtual key 0x{vkey:02X}",
                                    if event == AEvent::Down {
                                        "key-down"
                                    } else {
                                        "key-up"
                                    }
                                ));
                            }
                            if matches!(mode, CaptureMode::One(expected) if vkey != expected)
                                || matches!(mode, CaptureMode::Chord(first, second) if vkey != first && vkey != second)
                            {
                                DestroyWindow(window);
                                return Err(
                                    "an unexpected key event came from the selected ESP HID device"
                                        .to_owned(),
                                );
                            }
                            if matches!(mode, CaptureMode::One(expected) if vkey == expected) {
                                events.push(event);
                                if event == AEvent::Up {
                                    up_at = Some(Instant::now());
                                }
                                if verify_key_tap(&events).is_err() && events.len() > 1 {
                                    DestroyWindow(window);
                                    return Err(verify_key_tap(&events).unwrap_err().to_owned());
                                }
                            }
                            if matches!(mode, CaptureMode::Chord(first, second) if vkey == first || vkey == second)
                            {
                                chord_events.push((vkey, event));
                                let all_released = match mode {
                                    CaptureMode::Chord(first, second) => {
                                        [first, second].iter().all(|expected| {
                                            chord_events.iter().any(|(captured, event)| {
                                                captured == expected && *event == AEvent::Up
                                            })
                                        })
                                    }
                                    _ => false,
                                };
                                if all_released {
                                    up_at = Some(Instant::now());
                                }
                            }
                        }
                        DefWindowProcW(window, message.message, message.wParam, message.lParam);
                    } else {
                        TranslateMessage(&message);
                        DispatchMessageW(&message);
                    }
                }
                if up_at.is_some_and(|instant| instant.elapsed() >= QUIET_AFTER_UP) {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            DestroyWindow(window);
            match mode {
                CaptureMode::Quiet => Ok(()),
                CaptureMode::One(_) => verify_key_tap(&events).map_err(str::to_owned),
                CaptureMode::Chord(first, second) => {
                    verify_two_key_chord(&chord_events, [first, second]).map_err(str::to_owned)
                }
            }
        }
    }

    unsafe fn read_key_event(
        raw_handle: isize,
        selected_device: HANDLE,
    ) -> Result<Option<(u16, AEvent)>, String> {
        let mut byte_count = 0_u32;
        if unsafe {
            GetRawInputData(
                raw_handle as _,
                RID_INPUT,
                ptr::null_mut(),
                &mut byte_count,
                size_of::<RAWINPUTHEADER>() as u32,
            )
        } == ERROR_U32
        {
            return Err("Windows could not size a raw keyboard event".to_owned());
        }
        let word_count = (byte_count as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; word_count];
        if unsafe {
            GetRawInputData(
                raw_handle as _,
                RID_INPUT,
                storage.as_mut_ptr().cast::<c_void>(),
                &mut byte_count,
                size_of::<RAWINPUTHEADER>() as u32,
            )
        } == ERROR_U32
        {
            return Err("Windows could not read a raw keyboard event".to_owned());
        }
        let raw = unsafe { &*storage.as_ptr().cast::<RAWINPUT>() };
        if raw.header.hDevice != selected_device || raw.header.dwType != RIM_TYPEKEYBOARD {
            return Ok(None);
        }
        let keyboard = unsafe { raw.data.keyboard };
        Ok(Some((
            keyboard.VKey,
            if u32::from(keyboard.Flags) & RI_KEY_BREAK == 0 {
                AEvent::Down
            } else {
                AEvent::Up
            },
        )))
    }
}

#[cfg(windows)]
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let Err(error) = windows_capture::run(&args) {
        eprintln!("HIL keyboard check failed: {error}");
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("keyferry-hil-check requires Windows Raw Input");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exactly_one_a_down_up() {
        assert_eq!(verify_key_tap(&[AEvent::Down, AEvent::Up]), Ok(()));
        assert!(verify_key_tap(&[AEvent::Down, AEvent::Down, AEvent::Up]).is_err());
        assert!(verify_key_tap(&[AEvent::Down]).is_err());
        assert!(verify_key_tap(&[AEvent::Up]).is_err());
    }

    #[test]
    fn accepts_only_one_overlapping_two_key_chord() {
        let expected = [0x5b, 0x52];
        assert_eq!(
            verify_two_key_chord(
                &[
                    (0x5b, AEvent::Down),
                    (0x52, AEvent::Down),
                    (0x52, AEvent::Up),
                    (0x5b, AEvent::Up),
                ],
                expected,
            ),
            Ok(())
        );
        assert!(verify_two_key_chord(
            &[
                (0x5b, AEvent::Down),
                (0x5b, AEvent::Up),
                (0x52, AEvent::Down),
                (0x52, AEvent::Up),
            ],
            expected,
        )
        .is_err());
        assert!(verify_two_key_chord(
            &[
                (0x5b, AEvent::Down),
                (0x52, AEvent::Down),
                (0x52, AEvent::Up),
            ],
            expected,
        )
        .is_err());
    }

    #[test]
    fn identifies_only_espressif_vid_pid_tokens_without_serial_output() {
        assert_eq!(
            esp_vid_pid(r"\\?\HID#VID_303A&PID_4004&MI_00#private-instance"),
            Some("VID_303A&PID_4004".to_owned())
        );
        assert_eq!(esp_vid_pid(r"\\?\HID#VID_1234&PID_4004#other"), None);
        assert_eq!(esp_vid_pid(r"\\?\HID#VID_303A&PID_ZZZZ#bad"), None);
    }

    #[test]
    fn descriptor_summary_is_stable_and_omits_instance_path() {
        assert_eq!(
            descriptor_line(
                "VID_303A&PID_4004",
                1,
                6,
                9,
                2,
                0,
                "page=0x0007,usage=0x00E0..0x00E7,report_id=0,report_count=1",
            ),
            "ESP HID descriptor: VID_303A&PID_4004; top_usage_page=0x0001; top_usage=0x0006; input_report_bytes=9; output_report_bytes=2; feature_report_bytes=0; input_button_caps=[page=0x0007,usage=0x00E0..0x00E7,report_id=0,report_count=1]"
        );
    }
}

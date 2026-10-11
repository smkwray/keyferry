//! Media Foundation inventory only; never activates a camera or starts a process.
use super::capture::Device;
use windows::{
    core::GUID,
    Win32::{
        Foundation::RPC_E_CHANGED_MODE,
        Media::MediaFoundation::*,
        System::Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED},
    },
};

struct Com(bool);
impl Drop for Com {
    fn drop(&mut self) {
        if self.0 {
            // Balanced only when this invocation initialized the calling thread.
            unsafe { CoUninitialize() };
        }
    }
}
struct MediaFoundation;
impl Drop for MediaFoundation {
    fn drop(&mut self) {
        unsafe {
            let _ = MFShutdown();
        }
    }
}
struct Activations(*mut Option<IMFActivate>, u32);
impl Drop for Activations {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // MF owns an array of count initialized interface pointers allocated by COM.
            unsafe {
                std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(
                    self.0,
                    self.1 as usize,
                ));
                CoTaskMemFree(Some(self.0.cast()));
            }
        }
    }
}

fn attribute(device: &IMFActivate, key: &GUID) -> windows::core::Result<String> {
    unsafe {
        let length = device.GetStringLength(key)?;
        if length > 32 * 1024 {
            return Err(windows::core::Error::empty());
        }
        let mut value = vec![0; length as usize + 1];
        device.GetString(key, &mut value, None)?;
        String::from_utf16(&value[..length as usize]).map_err(|_| windows::core::Error::empty())
    }
}

fn map_device(name: String, link: String) -> Result<Device, &'static str> {
    if name.is_empty() || !link.starts_with(r"\\?\") || name.contains('\0') || link.contains('\0') {
        return Err("capture.list_failed");
    }
    // MF uses the video-camera interface category; DirectShow uses KSCATEGORY_CAPTURE.
    // Preserve the unique device path, translating the category before prefixing the moniker.
    // See FFmpeg libavdevice/dshow.c dshow_cycle_devices.
    Ok(Device {
        name,
        id: format!("@device_pnp_{link}")
            .replace(
                "{e5323777-f976-4f5b-9b55-b94699c46e44}",
                "{65e8773d-8f56-11d0-a3b9-00a0c9223196}",
            )
            .replace(':', "_"),
    })
}

pub(super) fn devices() -> Result<Vec<Device>, &'static str> {
    let enumerate = || -> windows::core::Result<Vec<Device>> {
        unsafe {
            let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
            if hr.is_err() && hr != RPC_E_CHANGED_MODE {
                hr.ok()?;
            }
            let _com = Com(hr.is_ok());
            MFStartup(MF_VERSION, MFSTARTUP_LITE)?;
            let _mf = MediaFoundation;
            let mut attributes = None;
            MFCreateAttributes(&mut attributes, 1)?;
            let attributes = attributes.ok_or_else(windows::core::Error::empty)?;
            attributes.SetGUID(
                &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
            )?;
            let mut sources = Activations(std::ptr::null_mut(), 0);
            MFEnumDeviceSources(&attributes, &mut sources.0, &mut sources.1)?;
            if sources.1 == 0 {
                return Ok(Vec::new());
            }
            if sources.0.is_null() {
                return Err(windows::core::Error::empty());
            }
            std::slice::from_raw_parts(sources.0, sources.1 as usize)
                .iter()
                .map(|source| {
                    let source = source.as_ref().ok_or_else(windows::core::Error::empty)?;
                    let name = attribute(source, &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME)?;
                    let link = attribute(
                        source,
                        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
                    )?;
                    map_device(name, link).map_err(|_| windows::core::Error::empty())
                })
                .collect()
        }
    };
    enumerate().map_err(|_| "capture.list_failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_driver_symbolic_link_to_unique_dshow_moniker() {
        // The synthetic instance survives unchanged while the public category translates.
        let link = r"\\?\usb#vid_345f&pid_2130&mi_00#synthetic-ms2130-instance#{e5323777-f976-4f5b-9b55-b94699c46e44}\global";
        let device = map_device("Hagibis".into(), link.into()).unwrap();
        assert_eq!(
            device.id,
            r"@device_pnp_\\?\usb#vid_345f&pid_2130&mi_00#synthetic-ms2130-instance#{65e8773d-8f56-11d0-a3b9-00a0c9223196}\global"
        );
        assert!(super::super::capture::recognized(&device));
        assert!(map_device(String::new(), link.into()).is_err());
        assert!(map_device("Camera".into(), "".into()).is_err());
    }
}

#![deny(unsafe_code)]
pub mod capture;
pub mod frames;
pub mod ocr;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_devices;

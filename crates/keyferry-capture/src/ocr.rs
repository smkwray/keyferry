//! Local OCR, in memory. Recognized text is returned only to the requesting client.
use super::frames::Frame;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct TextBox {
    pub text: String,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

pub trait Ocr {
    fn recognize(&mut self, frame: &Frame) -> Result<Vec<TextBox>, &'static str>;
}

pub struct NativeOcr;

impl Ocr for NativeOcr {
    fn recognize(&mut self, frame: &Frame) -> Result<Vec<TextBox>, &'static str> {
        recognize(frame)
    }
}

#[cfg(not(windows))]
fn recognize(_: &Frame) -> Result<Vec<TextBox>, &'static str> {
    Err("ocr.unsupported_platform")
}

#[cfg(windows)]
fn recognize(frame: &Frame) -> Result<Vec<TextBox>, &'static str> {
    use windows::{
        Graphics::Imaging::{BitmapPixelFormat, SoftwareBitmap},
        Media::Ocr::OcrEngine,
        Storage::Streams::DataWriter,
    };
    // Safe WinRT wrappers initialize activation through windows-core's factory machinery.
    // The engine uses locally installed user language packs; no cloud recognizer.
    let work = || -> windows::core::Result<Vec<TextBox>> {
        let engine = OcrEngine::TryCreateFromUserProfileLanguages()?;
        if frame.width > OcrEngine::MaxImageDimension()?
            || frame.height > OcrEngine::MaxImageDimension()?
        {
            return Err(windows::core::Error::empty());
        }
        let mut bgra = Vec::with_capacity(frame.rgb.len() / 3 * 4);
        for p in frame.rgb.chunks_exact(3) {
            bgra.extend_from_slice(&[p[2], p[1], p[0], 255]);
        }
        let writer = DataWriter::new()?;
        writer.WriteBytes(&bgra)?;
        let bitmap = SoftwareBitmap::CreateCopyFromBuffer(
            &writer.DetachBuffer()?,
            BitmapPixelFormat::Bgra8,
            frame.width as i32,
            frame.height as i32,
        )?;
        let result = engine.RecognizeAsync(&bitmap)?.join()?;
        let mut boxes = Vec::new();
        for line in result.Lines()? {
            let mut x0 = f64::INFINITY;
            let mut y0 = f64::INFINITY;
            let mut x1: f64 = 0.0;
            let mut y1: f64 = 0.0;
            for word in line.Words()? {
                let r = word.BoundingRect()?;
                x0 = x0.min(f64::from(r.X));
                y0 = y0.min(f64::from(r.Y));
                x1 = x1.max(f64::from(r.X + r.Width));
                y1 = y1.max(f64::from(r.Y + r.Height));
            }
            if x0.is_finite() && y0.is_finite() {
                boxes.push(TextBox {
                    text: line.Text()?.to_string(),
                    x: x0,
                    y: y0,
                    width: x1 - x0,
                    height: y1 - y0,
                });
            }
        }
        bitmap.Close()?;
        Ok(boxes)
    };
    work().map_err(|_| "ocr.engine_unavailable")
}

pub fn filter(boxes: Vec<TextBox>, query: Option<&str>) -> Vec<TextBox> {
    let query = query.map(str::to_lowercase);
    boxes
        .into_iter()
        .filter(|b| {
            query
                .as_ref()
                .is_none_or(|q| b.text.to_lowercase().contains(q))
        })
        .collect()
}

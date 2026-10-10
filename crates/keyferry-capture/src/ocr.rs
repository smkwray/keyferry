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

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use ab_glyph::{point, Font, FontRef, PxScale, ScaleFont};
    use std::{collections::HashMap, time::Instant};

    const WORDS: &[&str] = &[
        "Settings",
        "Network",
        "Display",
        "Invoice",
        "Wednesday",
        "Download",
        "Properties",
        "Bluetooth",
        "Schedule",
        "Approved",
        "Pending",
        "Calendar",
        "Firewall",
        "Terminal",
        "Shipping",
        "Account",
        "Quarterly",
        "Advanced",
        "Recovery",
        "Template",
    ];

    /// Deterministic UI-like tokens: words, versions, codes and file names.
    fn tokens(seed: &mut u32, count: usize) -> Vec<String> {
        let mut next = || {
            *seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *seed >> 8
        };
        (0..count)
            .map(|_| match next() % 4 {
                0 | 1 => WORDS[next() as usize % WORDS.len()].to_owned(),
                2 => format!("v{}.{}.{}", next() % 10, next() % 40, next() % 100),
                _ => format!(
                    "{}{}",
                    WORDS[next() as usize % WORDS.len()].to_lowercase(),
                    next() % 1000
                ),
            })
            .collect()
    }

    /// Black anti-aliased text on white, as on a light desktop at 100% scaling.
    fn render(font: &FontRef, size: f32, seed: &mut u32) -> (Frame, Vec<String>) {
        let (width, height) = (1920_u32, 1080_u32);
        let mut rgb = vec![255_u8; (width * height * 3) as usize];
        let scaled = font.as_scaled(PxScale::from(size));
        let mut expected = Vec::new();
        let mut baseline = 40.0 + size;
        while baseline < height as f32 - 40.0 {
            let mut caret = 40.0;
            for token in tokens(seed, 40) {
                let advance: f32 = token
                    .chars()
                    .map(|c| scaled.h_advance(font.glyph_id(c)))
                    .sum();
                if caret + advance > width as f32 - 40.0 {
                    break;
                }
                for c in token.chars() {
                    let id = font.glyph_id(c);
                    let glyph = id.with_scale_and_position(size, point(caret, baseline));
                    caret += scaled.h_advance(id);
                    let Some(outline) = font.outline_glyph(glyph) else {
                        continue;
                    };
                    let b = outline.px_bounds();
                    outline.draw(|x, y, coverage| {
                        let (x, y) = (b.min.x as i64 + i64::from(x), b.min.y as i64 + i64::from(y));
                        if (0..i64::from(width)).contains(&x) && (0..i64::from(height)).contains(&y)
                        {
                            let i = (y as usize * width as usize + x as usize) * 3;
                            let v = (255.0 * (1.0 - coverage.min(1.0))).round() as u8;
                            for p in &mut rgb[i..i + 3] {
                                *p = (*p).min(v);
                            }
                        }
                    });
                }
                caret += scaled.h_advance(font.glyph_id(' ')) * 1.6;
                expected.push(token);
            }
            baseline += size * 2.2;
        }
        let frame = Frame {
            width,
            height,
            native: (width, height),
            rgb,
            serial: 1,
            generation: 1,
            at: Instant::now(),
        };
        (frame, expected)
    }

    fn recall(boxes: &[TextBox], expected: &[String]) -> f64 {
        let mut seen = HashMap::<&str, usize>::new();
        for word in boxes.iter().flat_map(|b| b.text.split_whitespace()) {
            *seen.entry(word).or_default() += 1;
        }
        let found = expected
            .iter()
            .filter(|t| match seen.get_mut(t.as_str()) {
                Some(n) if *n > 0 => {
                    *n -= 1;
                    true
                }
                _ => false,
            })
            .count();
        found as f64 / expected.len() as f64
    }

    /// Before/after measurement for the native 1080p capture: OCR token recall on the
    /// native frame versus the 1280x720 view the card previously delivered, plus encode cost.
    /// Prints metrics only; the fixture is synthetic and never written to disk.
    #[test]
    #[ignore = "Windows OCR benchmark: cargo test -p keyferry-capture --lib small_text -- --ignored --nocapture"]
    fn small_text_ocr_and_encode_native_versus_720p_view() {
        let bytes = std::fs::read(r"C:\Windows\Fonts\segoeui.ttf").expect("Segoe UI");
        let font = FontRef::try_from_slice(&bytes).expect("font");
        let mut seed = 0x6b66_3130;
        for size in [10.0, 12.0, 14.0, 16.0, 18.0, 20.0] {
            let (native, expected) = render(&font, size, &mut seed);
            let started = Instant::now();
            let view = native.resized(1280, 720);
            let resize_ms = started.elapsed().as_secs_f64() * 1e3;
            let mut metrics =
                serde_json::json!({"text_px":size,"tokens":expected.len(),"resize_ms":resize_ms});
            for (name, frame) in [("native_1920x1080", &native), ("view_1280x720", &view)] {
                let started = Instant::now();
                let png = frame.png().unwrap();
                let encode_ms = started.elapsed().as_secs_f64() * 1e3;
                let started = Instant::now();
                let boxes = recognize(frame).unwrap();
                let ocr_ms = started.elapsed().as_secs_f64() * 1e3;
                metrics[name] = serde_json::json!({"token_recall":recall(&boxes, &expected),
                    "ocr_ms":ocr_ms,"png_bytes":png.len(),"png_encode_ms":encode_ms});
            }
            println!("{metrics}");
        }
    }
}

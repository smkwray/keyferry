//! Cursor binding evidence and nonsecret geometry. No retained frames or OCR text.
use super::frames::{pixel_changed, Frame, MotionMask};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Geometry {
    pub schema: String,
    pub device: String,
    pub source: String,
    pub native: (u32, u32),
    pub screenshot: (u32, u32),
    pub origin: [f64; 2],
    pub extent: [f64; 2],
}

impl Geometry {
    pub fn active_rectangle(&self) -> [f64; 4] {
        let x = self.origin[0].max(0.0);
        let y = self.origin[1].max(0.0);
        let right = (self.origin[0] + self.extent[0]).min(f64::from(self.screenshot.0 - 1));
        let bottom = (self.origin[1] + self.extent[1]).min(f64::from(self.screenshot.1 - 1));
        [
            x,
            y,
            (right - x + 1.0).max(0.0),
            (bottom - y + 1.0).max(0.0),
        ]
    }
    /// The same binding in a proportionally scaled view of the fitted frame. Pixel centres
    /// correspond: view coordinate u covers fitted coordinate (u + 0.5) / s - 0.5.
    pub fn scaled(&self, width: u32, height: u32) -> Geometry {
        let s = [
            f64::from(width) / f64::from(self.screenshot.0),
            f64::from(height) / f64::from(self.screenshot.1),
        ];
        Geometry {
            screenshot: (width, height),
            origin: [0, 1].map(|a| (self.origin[a] + 0.5) * s[a] - 0.5),
            extent: [0, 1].map(|a| self.extent[a] * s[a]),
            ..self.clone()
        }
    }
    pub fn matches(&self, device: &str, source: &str, f: &Frame) -> bool {
        self.schema == "keyferry.capture-geometry.v1"
            && self.device == device
            && self.source == source
            && self.native == f.native
            && self.screenshot == (f.width, f.height)
            && self.valid()
    }
    fn valid(&self) -> bool {
        self.origin
            .iter()
            .chain(&self.extent)
            .all(|v| v.is_finite())
            && self.extent[0] >= 32.0
            && self.extent[1] >= 32.0
            && self.extent[0] <= f64::from(self.screenshot.0) * 1.5
            && self.extent[1] <= f64::from(self.screenshot.1) * 1.5
            && self.origin[0].abs() <= f64::from(self.screenshot.0)
            && self.origin[1].abs() <= f64::from(self.screenshot.1)
    }
    pub fn map(&self, x: f64, y: f64) -> Result<[f64; 2], &'static str> {
        let p = [
            (x - self.origin[0]) / self.extent[0],
            (y - self.origin[1]) / self.extent[1],
        ];
        if !self.valid() || !p.iter().all(|v| v.is_finite() && (0.0..=1.0).contains(v)) {
            return Err("pointer.outside_active_video");
        }
        Ok(p)
    }
}

pub(super) fn linear(f: &Frame, x: f64, y: f64) -> Result<[f64; 2], &'static str> {
    if f.width < 2
        || f.height < 2
        || !x.is_finite()
        || !y.is_finite()
        || x < 0.0
        || y < 0.0
        || x > f64::from(f.width - 1)
        || y > f64::from(f.height - 1)
    {
        return Err("input.coordinates");
    }
    Ok([x / f64::from(f.width - 1), y / f64::from(f.height - 1)])
}

/// Intersection of two temporal differences isolates the cursor in the middle frame.
/// Two compact components or animation reject rather than guess a binding.
pub(super) fn cursor(
    a: &Frame,
    b: &Frame,
    c: &Frame,
    ignored: &MotionMask,
) -> Result<[f64; 2], &'static str> {
    cursor_near(a, b, c, ignored, None)
}

pub(super) fn cursor_near(
    a: &Frame,
    b: &Frame,
    c: &Frame,
    ignored: &MotionMask,
    target: Option<[f64; 2]>,
) -> Result<[f64; 2], &'static str> {
    let key = |f: &Frame| (f.width, f.height, f.native, f.generation);
    if key(a) != key(b) || key(b) != key(c) {
        return Err("capture.geometry_changed");
    }
    let count = b.width as usize * b.height as usize;
    let mut mask = vec![false; count];
    // Validates the mask's frame binding before indexing it.
    ignored.changed(a, b)?;
    if target.is_none() && !ignored.small() {
        return Err("calibration.animated_or_ambiguous");
    }
    for (i, marked) in mask.iter_mut().enumerate() {
        let k = i * 3;
        let in_roi = target.is_none_or(|target| {
            let x = (i % b.width as usize) as f64;
            let y = (i / b.width as usize) as f64;
            x >= target[0] - 16.0
                && x <= target[0] + 96.0
                && y >= target[1] - 16.0
                && y <= target[1] + 96.0
        });
        *marked = in_roi
            && !ignored.ignored(i)
            && pixel_changed(&a.rgb[k..k + 3], &b.rgb[k..k + 3])
            && pixel_changed(&b.rgb[k..k + 3], &c.rgb[k..k + 3]);
    }
    if target.is_none() && mask.iter().filter(|v| **v).count() > count / 50 {
        return Err("calibration.animated_or_ambiguous");
    }
    let mut candidates = Vec::new();
    for i in 0..count {
        if !mask[i] {
            continue;
        }
        mask[i] = false;
        let mut todo = vec![i];
        let (mut x0, mut y0, mut x1, mut y1, mut area) = (b.width, b.height, 0, 0, 0);
        while let Some(k) = todo.pop() {
            let (x, y) = (k as u32 % b.width, k as u32 / b.width);
            x0 = x0.min(x);
            y0 = y0.min(y);
            x1 = x1.max(x);
            y1 = y1.max(y);
            area += 1;
            // Nearest-neighbour downscaling drops whole rows/columns of a one-pixel arrow
            // outline; bridging gaps up to two pixels keeps the cursor one component.
            for dy in -2_i64..=2 {
                for dx in -2_i64..=2 {
                    let (xx, yy) = (i64::from(x) + dx, i64::from(y) + dy);
                    if xx >= 0 && yy >= 0 && xx < i64::from(b.width) && yy < i64::from(b.height) {
                        let n = yy as usize * b.width as usize + xx as usize;
                        if mask[n] {
                            mask[n] = false;
                            todo.push(n);
                        }
                    }
                }
            }
        }
        if (6..=2500).contains(&area)
            && x1 - x0 >= 2
            && y1 - y0 >= 2
            && x1 - x0 <= 80
            && y1 - y0 <= 80
        {
            let point = [f64::from(x0), f64::from(y0)];
            if target
                .is_none_or(|target| (0..2).all(|axis| (target[axis] - point[axis]).abs() <= 12.0))
            {
                candidates.push(point);
            }
        }
    }
    match candidates.as_slice() {
        [p] => Ok(*p),
        [] => Err("calibration.cursor_not_seen"),
        _ => Err("calibration.animated_or_ambiguous"),
    }
}

/// Frame rectangle `[x, y, width, height]` inside uniform black pillar/letterbox bars.
/// Bars are bounded to a quarter of each side so a dark desktop cannot collapse it.
pub(super) fn active_video(f: &Frame) -> [f64; 4] {
    let dark = |x: u32, y: u32| {
        let i = (y * f.width + x) as usize * 3;
        f.rgb[i..i + 3].iter().all(|v| *v <= 24)
    };
    let column = |x: u32| (0..f.height).all(|y| dark(x, y));
    let row = |y: u32| (0..f.width).all(|x| dark(x, y));
    let (mut left, mut right, mut top, mut bottom) = (0, f.width, 0, f.height);
    while left < f.width / 4 && column(left) {
        left += 1;
    }
    while right > f.width - f.width / 4 && column(right - 1) {
        right -= 1;
    }
    while top < f.height / 4 && row(top) {
        top += 1;
    }
    while bottom > f.height - f.height / 4 && row(bottom - 1) {
        bottom -= 1;
    }
    [left, top, right - left, bottom - top].map(f64::from)
}

/// Expected cursor pixel for normalized probe `p` before a geometry exists: a provisional
/// fit once at least three probes agree within the fit tolerance, otherwise the active
/// video rectangle (bars excluded), never the whole frame.
pub(super) fn expected(f: &Frame, samples: &[([f64; 2], [f64; 2])], p: [f64; 2]) -> [f64; 2] {
    let [x, y, width, height] = active_video(f);
    let bars = [x + p[0] * (width - 1.0), y + p[1] * (height - 1.0)];
    if samples.len() < 3 {
        return bars;
    }
    let lines = [line(samples, 0), line(samples, 1)];
    let agree = lines.iter().enumerate().all(|(axis, l)| {
        l.is_some_and(|(origin, extent)| {
            samples
                .iter()
                .all(|(p, q)| (q[axis] - origin - extent * p[axis]).abs() <= 5.0)
        })
    });
    match lines {
        [Some(a), Some(b)] if agree => [a.0 + a.1 * p[0], b.0 + b.1 * p[1]],
        _ => bars,
    }
}

/// Least-squares `(origin, extent)` for one axis; `None` when the probes do not span it.
fn line(samples: &[([f64; 2], [f64; 2])], axis: usize) -> Option<(f64, f64)> {
    let n = samples.len() as f64;
    let sx: f64 = samples.iter().map(|(p, _)| p[axis]).sum();
    let sy: f64 = samples.iter().map(|(_, q)| q[axis]).sum();
    let sxx: f64 = samples.iter().map(|(p, _)| p[axis] * p[axis]).sum();
    let sxy: f64 = samples.iter().map(|(p, q)| p[axis] * q[axis]).sum();
    let denom = n * sxx - sx * sx;
    if denom.abs() < 0.01 {
        return None;
    }
    let extent = (n * sxy - sx * sy) / denom;
    Some(((sy - extent * sx) / n, extent))
}

pub(super) fn residual(g: &Geometry, samples: &[([f64; 2], [f64; 2])]) -> f64 {
    samples
        .iter()
        .map(|(p, q)| {
            (0..2)
                .map(|axis| (q[axis] - g.origin[axis] - g.extent[axis] * p[axis]).powi(2))
                .sum::<f64>()
        })
        .sum::<f64>()
        / samples.len() as f64
}

/// Bounded consensus fit: at most two contaminated probes may be rejected, with at least
/// four agreeing points and an independent verification move still required by the caller.
pub(super) fn robust_fit(
    device: &str,
    source: &str,
    frame: &Frame,
    samples: &[([f64; 2], [f64; 2])],
) -> Result<(Geometry, usize, f64), &'static str> {
    if !(4..=10).contains(&samples.len()) {
        return Err("calibration.insufficient_samples");
    }
    let mut best = None;
    for subset in 0_u16..(1 << samples.len()) {
        if subset.count_ones() != 4 {
            continue;
        }
        let chosen: Vec<_> = samples
            .iter()
            .enumerate()
            .filter(|(i, _)| subset & (1 << i) != 0)
            .map(|(_, s)| *s)
            .collect();
        let Ok(g) = fit(device, source, frame, &chosen) else {
            continue;
        };
        let inliers: Vec<_> = samples
            .iter()
            .filter(|(p, q)| {
                (0..2)
                    .all(|axis| (q[axis] - g.origin[axis] - g.extent[axis] * p[axis]).abs() <= 5.0)
            })
            .copied()
            .collect();
        if inliers.len() < 4.max(samples.len().saturating_sub(2)) {
            continue;
        }
        let Ok(g) = fit(device, source, frame, &inliers) else {
            continue;
        };
        let rms = residual(&g, &inliers).sqrt();
        if best.as_ref().is_none_or(|(_, count, error)| {
            inliers.len() > *count || (inliers.len() == *count && rms < *error)
        }) {
            best = Some((g, inliers.len(), rms));
        }
    }
    best.ok_or("calibration.mapping_mismatch")
}

/// Fit independent affine axes. Scaling, bars and capture overscan become one geometry.
pub(super) fn fit(
    device: &str,
    source: &str,
    frame: &Frame,
    samples: &[([f64; 2], [f64; 2])],
) -> Result<Geometry, &'static str> {
    if samples.len() < 4 {
        return Err("calibration.insufficient_samples");
    }
    let mut origin = [0.0; 2];
    let mut extent = [0.0; 2];
    for axis in 0..2 {
        (origin[axis], extent[axis]) = line(samples, axis).ok_or("calibration.degenerate")?;
    }
    let g = Geometry {
        schema: "keyferry.capture-geometry.v1".into(),
        device: device.into(),
        source: source.into(),
        native: frame.native,
        screenshot: (frame.width, frame.height),
        origin,
        extent,
    };
    if !g.valid()
        || samples
            .iter()
            .any(|(p, q)| (0..2).any(|a| (q[a] - origin[a] - extent[a] * p[a]).abs() > 5.0))
    {
        return Err("calibration.mapping_mismatch");
    }
    Ok(g)
}

fn path(root: &Path, device: &str, source: &str) -> PathBuf {
    let hash = Sha256::digest(source.as_bytes());
    root.join(format!("{device}-{:x}.json", hash))
}

pub(super) fn load(
    root: &Path,
    device: &str,
    source: &str,
) -> Result<Option<Geometry>, &'static str> {
    let mut f = match fs::File::open(path(root, device, source)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("calibration.read_failed"),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| "calibration.read_failed")?;
    if bytes.len() > 8192 {
        return Err("calibration.invalid_record");
    }
    let g: Geometry = serde_json::from_slice(&bytes).map_err(|_| "calibration.invalid_record")?;
    if !g.valid() || g.device != device || g.source != source {
        return Err("calibration.invalid_record");
    }
    Ok(Some(g))
}

pub(super) fn save(root: &Path, g: &Geometry) -> Result<(), &'static str> {
    fs::create_dir_all(root).map_err(|_| "calibration.write_failed")?;
    let dest = path(root, &g.device, &g.source);
    let tmp = root.join(format!(".geometry-{}.tmp", uuid::Uuid::now_v7()));
    let bytes = serde_json::to_vec(g).map_err(|_| "calibration.invalid_record")?;
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| "calibration.write_failed")?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "calibration.write_failed")?;
        drop(file);
        fs::rename(&tmp, &dest).map_err(|_| "calibration.write_failed")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

//! Each stick's name is its model, read from the board id the stick itself reports.
//!
//! The last board seen for each stick is remembered, optionally in a small file beside the
//! local token, so an offline stick keeps its model name across restarts. It holds device ids
//! and board numbers only.

use keyferry_protocol::firmware_identity::board_model_name;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io, path::PathBuf, sync::Mutex};

pub(crate) const FILE_NAME: &str = "device-models.json";
const SCHEMA: u32 = 1;
/// Shown until this controller has seen the stick report its board once.
pub const UNKNOWN_MODEL: &str = "Unknown model";

#[derive(Default)]
pub(crate) struct ModelMemory(Mutex<State>);

#[derive(Default)]
struct State {
    path: Option<PathBuf>,
    boards: BTreeMap<String, u32>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    schema: u32,
    boards: BTreeMap<String, u32>,
}

impl ModelMemory {
    /// Loads the remembered boards from `path` and keeps later sightings there.
    /// A missing file starts empty; an unreadable one is reported and replaced on the next sighting.
    pub(crate) fn persist_at(&self, path: PathBuf) {
        let loaded = match fs::read(&path) {
            Ok(bytes) => match parse(&bytes) {
                Ok(boards) => boards,
                Err(reason) => {
                    crate::daemon_log!(
                        "device model memory unreadable ({reason}); stick names start from live reports"
                    );
                    BTreeMap::new()
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => {
                crate::daemon_log!(
                    "device model memory unreadable ({}); stick names start from live reports",
                    error.kind()
                );
                BTreeMap::new()
            }
        };
        let mut state = self.0.lock().expect("model memory lock");
        crate::daemon_log!("device model memory: {} remembered stick(s)", loaded.len());
        for (device, board) in loaded {
            state.boards.entry(device).or_insert(board);
        }
        state.path = Some(path);
    }

    /// The stick's model name: the board it reports now, else the last board it reported.
    /// A live report is remembered (and saved when it changes).
    pub(crate) fn name(&self, device: &str, live_board: Option<u32>) -> Option<&'static str> {
        let mut state = self.0.lock().expect("model memory lock");
        if let Some(board) = live_board.filter(|board| board_model_name(*board).is_some()) {
            if state.boards.get(device) != Some(&board) {
                state.boards.insert(device.to_owned(), board);
                if let Some(path) = &state.path {
                    if let Err(error) = save(path, &state.boards) {
                        crate::daemon_log!(
                            "device model memory not saved ({}); names still follow live reports",
                            error.kind()
                        );
                    }
                }
            }
        }
        state.boards.get(device).copied().and_then(board_model_name)
    }
}

fn parse(bytes: &[u8]) -> Result<BTreeMap<String, u32>, &'static str> {
    let stored: Stored = serde_json::from_slice(bytes).map_err(|_| "malformed")?;
    if stored.schema != SCHEMA {
        return Err("unsupported schema");
    }
    if stored.boards.iter().any(|(device, board)| {
        uuid::Uuid::parse_str(device).is_err() || board_model_name(*board).is_none()
    }) {
        return Err("unknown device or board");
    }
    Ok(stored.boards)
}

fn save(path: &std::path::Path, boards: &BTreeMap<String, u32>) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(&Stored {
        schema: SCHEMA,
        boards: boards.clone(),
    })
    .map_err(io::Error::other)?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyferry_protocol::firmware_identity::{
        BOARD_LILYGO_T_DONGLE_S3, BOARD_M5STACK_ATOMS3_LITE, BOARD_WAVESHARE_GEEK_V1_1_REFERENCE,
    };

    const LILYGO: &str = "11111111-0000-4000-8000-000000000002";
    const ATOM: &str = "22222222-0000-4000-8000-000000000003";

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyferry-models-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn live_board_names_the_stick_and_is_remembered_after_it_goes_offline() {
        let memory = ModelMemory::default();
        assert_eq!(memory.name(LILYGO, None), None);
        assert_eq!(
            memory.name(LILYGO, Some(BOARD_LILYGO_T_DONGLE_S3)),
            Some("LILYGO")
        );
        // Offline: no live report, the remembered model still names it.
        assert_eq!(memory.name(LILYGO, None), Some("LILYGO"));
        // A different board reported for the same id (reflashed onto other hardware) wins.
        assert_eq!(
            memory.name(LILYGO, Some(BOARD_WAVESHARE_GEEK_V1_1_REFERENCE)),
            Some("Waveshare GEEK")
        );
        // An unregistered live board never replaces a known model.
        assert_eq!(memory.name(LILYGO, Some(99)), Some("Waveshare GEEK"));
        assert_eq!(memory.name(ATOM, Some(99)), None);
    }

    #[test]
    fn remembered_models_survive_a_restart() {
        let dir = temp_dir("restart");
        let path = dir.join(FILE_NAME);
        let first = ModelMemory::default();
        first.persist_at(path.clone());
        first.name(LILYGO, Some(BOARD_LILYGO_T_DONGLE_S3));
        first.name(ATOM, Some(BOARD_M5STACK_ATOMS3_LITE));
        assert!(!path.with_extension("json.tmp").exists());

        let restarted = ModelMemory::default();
        restarted.persist_at(path.clone());
        assert_eq!(restarted.name(LILYGO, None), Some("LILYGO"));
        assert_eq!(restarted.name(ATOM, None), Some("AtomS3 Lite"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn unreadable_memory_starts_empty_and_is_replaced_by_the_next_report() {
        for corrupt in [
            &b"not json"[..],
            br#"{"schema":2,"boards":{}}"#,
            br#"{"schema":1,"boards":{"not-a-uuid":2}}"#,
            br#"{"schema":1,"boards":{"11111111-0000-4000-8000-000000000002":99}}"#,
            br#"{"schema":1,"boards":{},"extra":true}"#,
        ] {
            let dir = temp_dir("corrupt");
            let path = dir.join(FILE_NAME);
            fs::write(&path, corrupt).expect("seed corrupt file");
            let memory = ModelMemory::default();
            memory.persist_at(path.clone());
            assert_eq!(memory.name(LILYGO, None), None);
            memory.name(LILYGO, Some(BOARD_LILYGO_T_DONGLE_S3));
            let reloaded = ModelMemory::default();
            reloaded.persist_at(path);
            assert_eq!(reloaded.name(LILYGO, None), Some("LILYGO"));
            fs::remove_dir_all(dir).expect("cleanup");
        }
    }
}

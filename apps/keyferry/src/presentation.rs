use crate::api::{CommandOutcome, EventRecord};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeTone {
    Neutral,
    Warning,
    Failure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeView {
    pub label: &'static str,
    pub explanation: &'static str,
    pub tone: OutcomeTone,
    pub show_success_tick: bool,
}

#[must_use]
pub const fn outcome_view(outcome: CommandOutcome) -> OutcomeView {
    match outcome {
        CommandOutcome::Queued => OutcomeView {
            label: "QUEUED",
            explanation: "Accepted into the daemon queue; execution has not started.",
            tone: OutcomeTone::Neutral,
            show_success_tick: false,
        },
        CommandOutcome::Accepted => OutcomeView {
            label: "ACCEPTED",
            explanation: "The daemon accepted the command; execution may not have started.",
            tone: OutcomeTone::Neutral,
            show_success_tick: false,
        },
        CommandOutcome::Started => OutcomeView {
            label: "STARTED",
            explanation:
                "Execution started; a later disconnect can make the final outcome unknown.",
            tone: OutcomeTone::Warning,
            show_success_tick: false,
        },
        CommandOutcome::Emitted => OutcomeView {
            label: "EMITTED",
            explanation: "USB reports were emitted; the target application is not observable.",
            tone: OutcomeTone::Warning,
            show_success_tick: false,
        },
        CommandOutcome::Aborted => OutcomeView {
            label: "ABORTED",
            explanation: "The daemon stopped the command before completion.",
            tone: OutcomeTone::Failure,
            show_success_tick: false,
        },
        CommandOutcome::Rejected => OutcomeView {
            label: "REJECTED",
            explanation: "The daemon refused the command; no delivery is claimed.",
            tone: OutcomeTone::Failure,
            show_success_tick: false,
        },
        CommandOutcome::Unknown => OutcomeView {
            label: "UNKNOWN",
            explanation: "The final outcome cannot be established; do not assume delivery.",
            tone: OutcomeTone::Failure,
            show_success_tick: false,
        },
    }
}

#[must_use]
pub fn render_diagnostic_event(event: &EventRecord) -> String {
    let outcome = outcome_view(event.outcome);
    format!(
        "{} · {} · command {} · device {} · profile {} · actions {} · chars {}",
        event.timestamp,
        outcome.label,
        safe_metadata(&event.command_id),
        safe_metadata(&event.device_id),
        safe_metadata(&event.profile),
        event.action_count,
        event.char_count
    )
}

fn safe_metadata(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emitted_is_not_application_delivery_and_unknown_has_no_success_tick() {
        let emitted = outcome_view(CommandOutcome::Emitted);
        assert_eq!(
            emitted.explanation,
            "USB reports were emitted; the target application is not observable."
        );
        assert!(!emitted.show_success_tick);

        let unknown = outcome_view(CommandOutcome::Unknown);
        assert_eq!(unknown.label, "UNKNOWN");
        assert!(!unknown.show_success_tick);
        assert!(unknown.explanation.contains("do not assume delivery"));
    }

    #[test]
    fn diagnostics_are_metadata_only_and_never_include_payload_text() {
        let event = EventRecord {
            command_id: "command-1".to_owned(),
            caller: "local".to_owned(),
            device_id: "device-1".to_owned(),
            profile: "windows-us".to_owned(),
            action_count: 4,
            char_count: 18,
            timestamp: "2026-09-01T00:00:00Z".to_owned(),
            duration_ms: Some(100),
            outcome: CommandOutcome::Unknown,
        };
        let payload = "private dictated payload";
        let rendered = render_diagnostic_event(&event);
        assert!(!rendered.contains(payload));
        assert!(!rendered.contains("USB reports were emitted"));
        assert!(!rendered.contains('✓'));
    }
}

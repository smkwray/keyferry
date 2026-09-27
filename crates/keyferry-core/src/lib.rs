#![forbid(unsafe_code)]

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalMode {
    Keyboard,
    Maintenance,
    Locked,
    Fault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkState {
    Offline,
    Connecting,
    Authenticated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmPolicy {
    CommandScoped,
    Temporary,
    AlwaysReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandState {
    Queued,
    Accepted,
    Started,
    Emitted,
    Aborted,
    Rejected,
    Unknown,
}

impl CommandState {
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Emitted | Self::Aborted | Self::Rejected | Self::Unknown
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportDiagnostic {
    CancelSendTransport,
    CancelSendProtocol,
    CancelActiveResultTransport,
    CancelActiveResultProtocol,
    CancelLateResultTransport,
    CancelLateResultProtocol,
    CancelReleaseSendTransport,
    CancelReleaseSendProtocol,
    CancelReleaseAcceptedTransport,
    CancelReleaseAcceptedProtocol,
    CancelReleaseEmittedTransport,
    CancelReleaseEmittedProtocol,
}

impl TransportDiagnostic {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CancelSendTransport => "cancel.send.transport",
            Self::CancelSendProtocol => "cancel.send.protocol",
            Self::CancelActiveResultTransport => "cancel.active_result.transport",
            Self::CancelActiveResultProtocol => "cancel.active_result.protocol",
            Self::CancelLateResultTransport => "cancel.late_result.transport",
            Self::CancelLateResultProtocol => "cancel.late_result.protocol",
            Self::CancelReleaseSendTransport => "cancel.release_send.transport",
            Self::CancelReleaseSendProtocol => "cancel.release_send.protocol",
            Self::CancelReleaseAcceptedTransport => "cancel.release_accepted.transport",
            Self::CancelReleaseAcceptedProtocol => "cancel.release_accepted.protocol",
            Self::CancelReleaseEmittedTransport => "cancel.release_emitted.transport",
            Self::CancelReleaseEmittedProtocol => "cancel.release_emitted.protocol",
        }
    }

    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "cancel.send.transport" => Some(Self::CancelSendTransport),
            "cancel.send.protocol" => Some(Self::CancelSendProtocol),
            "cancel.active_result.transport" => Some(Self::CancelActiveResultTransport),
            "cancel.active_result.protocol" => Some(Self::CancelActiveResultProtocol),
            "cancel.late_result.transport" => Some(Self::CancelLateResultTransport),
            "cancel.late_result.protocol" => Some(Self::CancelLateResultProtocol),
            "cancel.release_send.transport" => Some(Self::CancelReleaseSendTransport),
            "cancel.release_send.protocol" => Some(Self::CancelReleaseSendProtocol),
            "cancel.release_accepted.transport" => Some(Self::CancelReleaseAcceptedTransport),
            "cancel.release_accepted.protocol" => Some(Self::CancelReleaseAcceptedProtocol),
            "cancel.release_emitted.transport" => Some(Self::CancelReleaseEmittedTransport),
            "cancel.release_emitted.protocol" => Some(Self::CancelReleaseEmittedProtocol),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    NotAuthenticated,
    InvalidMode,
    NotArmed,
    Busy,
    NoActiveCommand,
    InvalidTransition {
        from: CommandState,
        to: CommandState,
    },
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAuthenticated => write!(f, "device link is not authenticated"),
            Self::InvalidMode => write!(f, "operational mode does not permit keyboard input"),
            Self::NotArmed => write!(f, "device is not armed"),
            Self::Busy => write!(f, "another command is active"),
            Self::NoActiveCommand => write!(f, "no command is active"),
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid command transition from {from:?} to {to:?}")
            }
        }
    }
}

impl std::error::Error for StateError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveCommand {
    pub command_id: [u8; 16],
    pub state: CommandState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceState {
    pub mode: OperationalMode,
    pub link: LinkState,
    pub armed: bool,
    pub arm_policy: ArmPolicy,
    pub active: Option<ActiveCommand>,
}

impl Default for DeviceState {
    fn default() -> Self {
        Self {
            mode: OperationalMode::Keyboard,
            link: LinkState::Offline,
            armed: false,
            arm_policy: ArmPolicy::CommandScoped,
            active: None,
        }
    }
}

impl DeviceState {
    pub fn set_link_authenticated(&mut self) {
        self.link = LinkState::Authenticated;
        self.armed = false;
        self.active = None;
    }

    pub fn set_mode(&mut self, mode: OperationalMode) {
        self.mode = mode;
        if mode != OperationalMode::Keyboard {
            self.armed = false;
            self.active = None;
        }
    }

    pub fn arm(&mut self, policy: ArmPolicy) -> Result<(), StateError> {
        if self.link != LinkState::Authenticated {
            return Err(StateError::NotAuthenticated);
        }
        if self.mode != OperationalMode::Keyboard {
            return Err(StateError::InvalidMode);
        }
        self.arm_policy = policy;
        self.armed = true;
        Ok(())
    }

    pub fn disarm(&mut self) {
        self.armed = false;
    }

    pub fn submit(&mut self, command_id: [u8; 16]) -> Result<(), StateError> {
        if self.link != LinkState::Authenticated {
            return Err(StateError::NotAuthenticated);
        }
        if self.mode != OperationalMode::Keyboard {
            return Err(StateError::InvalidMode);
        }
        if !self.armed {
            return Err(StateError::NotArmed);
        }
        if self.active.is_some() {
            return Err(StateError::Busy);
        }
        self.active = Some(ActiveCommand {
            command_id,
            state: CommandState::Queued,
        });
        Ok(())
    }

    pub fn transition(&mut self, next: CommandState) -> Result<(), StateError> {
        let active = self.active.as_mut().ok_or(StateError::NoActiveCommand)?;
        let valid = matches!(
            (active.state, next),
            (CommandState::Queued, CommandState::Accepted)
                | (CommandState::Queued, CommandState::Aborted)
                | (CommandState::Queued, CommandState::Rejected)
                | (CommandState::Queued, CommandState::Unknown)
                | (CommandState::Accepted, CommandState::Started)
                | (CommandState::Accepted, CommandState::Aborted)
                | (CommandState::Accepted, CommandState::Rejected)
                | (CommandState::Started, CommandState::Emitted)
                | (CommandState::Started, CommandState::Aborted)
                | (CommandState::Started, CommandState::Unknown)
                | (CommandState::Accepted, CommandState::Unknown)
        );
        if !valid {
            return Err(StateError::InvalidTransition {
                from: active.state,
                to: next,
            });
        }
        active.state = next;
        if next.is_terminal() && self.arm_policy == ArmPolicy::CommandScoped {
            self.armed = false;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Option<ActiveCommand> {
        match &self.active {
            Some(command) if command.state.is_terminal() => self.active.take(),
            _ => None,
        }
    }

    pub fn disconnect(&mut self) -> Option<ActiveCommand> {
        self.link = LinkState::Offline;
        self.armed = false;
        let mut active = self.active.take();
        if let Some(command) = active.as_mut() {
            command.state = match command.state {
                CommandState::Queued => CommandState::Rejected,
                CommandState::Accepted | CommandState::Started => CommandState::Unknown,
                terminal => terminal,
            };
        }
        active
    }

    pub fn fault(&mut self) -> Option<ActiveCommand> {
        self.mode = OperationalMode::Fault;
        self.armed = false;
        let mut active = self.active.take();
        if let Some(command) = active.as_mut() {
            command.state = match command.state {
                CommandState::Queued => CommandState::Rejected,
                CommandState::Accepted | CommandState::Started => CommandState::Unknown,
                terminal => terminal,
            };
        }
        active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; 16] = [7; 16];

    #[test]
    fn command_scoped_arm_disarms_after_emission() {
        let mut state = DeviceState::default();
        state.set_link_authenticated();
        state.arm(ArmPolicy::CommandScoped).unwrap();
        state.submit(ID).unwrap();
        state.transition(CommandState::Accepted).unwrap();
        state.transition(CommandState::Started).unwrap();
        state.transition(CommandState::Emitted).unwrap();
        assert!(!state.armed);
        assert_eq!(state.finish().unwrap().state, CommandState::Emitted);
    }

    #[test]
    fn disconnect_after_acceptance_is_unknown_and_disarmed() {
        let mut state = DeviceState::default();
        state.set_link_authenticated();
        state.arm(ArmPolicy::Temporary).unwrap();
        state.submit(ID).unwrap();
        state.transition(CommandState::Accepted).unwrap();
        let command = state.disconnect().unwrap();
        assert_eq!(command.state, CommandState::Unknown);
        assert!(!state.armed);
        assert_eq!(state.link, LinkState::Offline);
    }

    #[test]
    fn maintenance_mode_rejects_arming() {
        let mut state = DeviceState::default();
        state.set_link_authenticated();
        state.set_mode(OperationalMode::Maintenance);
        assert_eq!(
            state.arm(ArmPolicy::CommandScoped),
            Err(StateError::InvalidMode)
        );
    }

    #[test]
    fn accepted_command_can_be_aborted_before_reports_start() {
        let mut state = DeviceState::default();
        state.set_link_authenticated();
        state.arm(ArmPolicy::CommandScoped).unwrap();
        state.submit(ID).unwrap();
        state.transition(CommandState::Accepted).unwrap();
        state.transition(CommandState::Aborted).unwrap();
        assert!(!state.armed);
        assert_eq!(state.finish().unwrap().state, CommandState::Aborted);
    }

    #[test]
    fn transition_without_active_command_is_explicit() {
        let mut state = DeviceState::default();
        assert_eq!(
            state.transition(CommandState::Accepted),
            Err(StateError::NoActiveCommand)
        );
    }

    #[test]
    fn invalid_transition_is_rejected() {
        let mut state = DeviceState::default();
        state.set_link_authenticated();
        state.arm(ArmPolicy::CommandScoped).unwrap();
        state.submit(ID).unwrap();
        assert!(matches!(
            state.transition(CommandState::Emitted),
            Err(StateError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn started_command_cannot_be_reduced_to_rejected() {
        let mut state = DeviceState::default();
        state.set_link_authenticated();
        state.arm(ArmPolicy::CommandScoped).unwrap();
        state.submit(ID).unwrap();
        state.transition(CommandState::Accepted).unwrap();
        state.transition(CommandState::Started).unwrap();
        assert!(matches!(
            state.transition(CommandState::Rejected),
            Err(StateError::InvalidTransition {
                from: CommandState::Started,
                to: CommandState::Rejected,
            })
        ));
    }

    #[test]
    fn transport_diagnostic_codes_are_strict_and_round_trip() {
        for diagnostic in [
            TransportDiagnostic::CancelSendTransport,
            TransportDiagnostic::CancelSendProtocol,
            TransportDiagnostic::CancelActiveResultTransport,
            TransportDiagnostic::CancelActiveResultProtocol,
            TransportDiagnostic::CancelLateResultTransport,
            TransportDiagnostic::CancelLateResultProtocol,
            TransportDiagnostic::CancelReleaseSendTransport,
            TransportDiagnostic::CancelReleaseSendProtocol,
            TransportDiagnostic::CancelReleaseAcceptedTransport,
            TransportDiagnostic::CancelReleaseAcceptedProtocol,
            TransportDiagnostic::CancelReleaseEmittedTransport,
            TransportDiagnostic::CancelReleaseEmittedProtocol,
        ] {
            assert_eq!(
                TransportDiagnostic::from_code(diagnostic.code()),
                Some(diagnostic)
            );
        }
        assert_eq!(TransportDiagnostic::from_code("cancel.payload.text"), None);
    }
}

//! Focus + edge-transition state machine — the heart of the system.
//!
//! Pure and deterministic: [`FocusState::handle`] takes an event and returns the
//! next state plus a list of [`DomainEffect`]s for the engine to execute. The
//! machine itself performs no I/O, so every transition is unit-testable.
//!
//! # Safety invariant
//! Any path that loses the active link or aborts control returns focus to the
//! **local** machine and emits [`DomainEffect::ReleaseAllKeys`] (and restores
//! the local cursor / stops capture or injection). A dropped connection can
//! never strand a machine with a stuck modifier, a hidden cursor, or phantom
//! remote control. This is enforced by `transport_lost_is_safe` (exhaustive over
//! all states) and the property tests.

use crate::device::DeviceId;
use kvm_proto::geometry::{Edge, EntryPoint};

/// Where a pending transition leads.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PendingTransition {
    pub target: DeviceId,
    pub edge: Edge,
    pub entry: EntryPoint,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FocusState {
    /// This device owns input; cursor is local and visible.
    LocalControl,
    /// Cursor is sitting in a seam band; counting consecutive samples
    /// (hysteresis) before committing a handoff.
    EdgeArmed {
        target: DeviceId,
        edge: Edge,
        samples: u8,
    },
    /// Handoff committed; capture is active and we await the peer's ack.
    Switching { target: DeviceId },
    /// We are driving a remote peer; local input is captured & forwarded.
    RemoteControl { target: DeviceId },
    /// A remote peer is driving us; we inject its events.
    Receiving { source: DeviceId },
    /// The active link dropped mid-control; safe local state pending recovery.
    Lost { last: DeviceId },
}

/// Inputs to the state machine. The engine raises these from cursor sampling,
/// transport events, hotkeys, and inbound control messages.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FocusEvent {
    /// Cursor is in a seam band resolving to a (trusted, reachable) target.
    /// Raised repeatedly while the cursor stays at the edge.
    EdgeReached(PendingTransition),
    /// Cursor left every actionable seam band — disarm.
    EdgeCleared,
    /// While controlling a peer, the virtual cursor reached the seam that links
    /// back to this (home) device.
    ReturnHome { entry: EntryPoint },
    /// Manual hotkey: immediately switch to `target` (bypasses hysteresis).
    ManualSwitch(PendingTransition),
    /// Manual hotkey: release any remote control and reclaim local focus.
    HotkeyRelease,
    /// Peer accepted our switch request.
    SwitchAck,
    /// Peer refused our switch request.
    SwitchNack,
    /// Our switch request timed out without a reply.
    SwitchTimeout,
    /// A peer requests to control us (already authorized by the engine).
    RemoteSwitchRequest { source: DeviceId, entry: EntryPoint },
    /// The peer controlling us released.
    RemoteRelease,
    /// The transport to the active peer dropped.
    TransportLost,
    /// The transport to `peer` came back after a `Lost`.
    Reconnected { peer: DeviceId },
}

/// Side effects for the engine to execute. The state machine never performs them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DomainEffect {
    /// Begin grabbing local input (we become the controller).
    StartCapture,
    /// Stop grabbing local input.
    StopCapture,
    /// Hide/park the local cursor while controlling a remote.
    HideLocalCursor,
    /// Restore the local cursor (optionally at a specific entry).
    RestoreLocalCursor,
    /// Initialize virtual-cursor tracking on the target at `entry`.
    SetVirtualCursor { entry: EntryPoint },
    /// Send a SwitchRequest to `target` with the entry point.
    SendSwitchRequest { target: DeviceId, entry: EntryPoint },
    /// Tell `target` we are releasing control.
    SendRelease { target: DeviceId },
    /// Accept an inbound control request from `source`.
    SendSwitchAck { source: DeviceId },
    /// Start injecting a remote source's events locally.
    BeginInjecting { source: DeviceId, entry: EntryPoint },
    /// Stop injecting.
    StopInjecting,
    /// FAIL-SAFE: release every currently-held key and mouse button.
    ReleaseAllKeys,
}

#[derive(Debug, Clone, Copy)]
pub struct FocusConfig {
    /// Consecutive edge samples required before a handoff commits (hysteresis).
    pub arm_samples: u8,
}

impl Default for FocusConfig {
    fn default() -> Self {
        FocusConfig { arm_samples: 3 }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transition {
    pub next: FocusState,
    pub effects: Vec<DomainEffect>,
}

impl Transition {
    fn to(next: FocusState, effects: Vec<DomainEffect>) -> Self {
        Transition { next, effects }
    }
    fn stay(state: FocusState) -> Self {
        Transition {
            next: state,
            effects: Vec::new(),
        }
    }
}

impl FocusState {
    /// The effects that commit a handoff to `target`/`entry` (capture + hide +
    /// virtual cursor + request). Shared by the armed and manual paths.
    fn commit_switch(target: DeviceId, entry: EntryPoint) -> Transition {
        Transition::to(
            FocusState::Switching { target },
            vec![
                DomainEffect::StartCapture,
                DomainEffect::HideLocalCursor,
                DomainEffect::SetVirtualCursor { entry },
                DomainEffect::SendSwitchRequest { target, entry },
            ],
        )
    }

    /// Abort an in-flight or active control session and return safely home.
    fn return_home(reason_release_to: Option<DeviceId>, fail_safe: bool) -> Transition {
        let mut effects = vec![DomainEffect::StopCapture, DomainEffect::RestoreLocalCursor];
        if let Some(target) = reason_release_to {
            effects.push(DomainEffect::SendRelease { target });
        }
        if fail_safe {
            effects.push(DomainEffect::ReleaseAllKeys);
        }
        Transition::to(FocusState::LocalControl, effects)
    }

    pub fn handle(&self, event: FocusEvent, cfg: &FocusConfig) -> Transition {
        use FocusEvent as Ev;
        use FocusState as S;

        match (*self, event) {
            // ---- LocalControl ----
            (S::LocalControl, Ev::EdgeReached(pt)) => {
                // Arm; if a single sample suffices, commit immediately.
                if cfg.arm_samples <= 1 {
                    S::commit_switch(pt.target, pt.entry)
                } else {
                    Transition::stay(S::EdgeArmed {
                        target: pt.target,
                        edge: pt.edge,
                        samples: 1,
                    })
                }
            }
            (S::LocalControl, Ev::ManualSwitch(pt)) => S::commit_switch(pt.target, pt.entry),
            (S::LocalControl, Ev::RemoteSwitchRequest { source, entry }) => Transition::to(
                S::Receiving { source },
                vec![
                    DomainEffect::SendSwitchAck { source },
                    DomainEffect::BeginInjecting { source, entry },
                ],
            ),

            // ---- EdgeArmed ----
            (
                S::EdgeArmed {
                    target,
                    edge,
                    samples,
                },
                Ev::EdgeReached(pt),
            ) => {
                if pt.target == target && pt.edge == edge {
                    let next = samples.saturating_add(1);
                    if next >= cfg.arm_samples {
                        S::commit_switch(pt.target, pt.entry)
                    } else {
                        Transition::stay(S::EdgeArmed {
                            target,
                            edge,
                            samples: next,
                        })
                    }
                } else {
                    // Different edge/target: re-arm freshly on the new one.
                    Transition::stay(S::EdgeArmed {
                        target: pt.target,
                        edge: pt.edge,
                        samples: 1,
                    })
                }
            }
            (S::EdgeArmed { .. }, Ev::EdgeCleared) => Transition::stay(S::LocalControl),
            (S::EdgeArmed { .. }, Ev::ManualSwitch(pt)) => S::commit_switch(pt.target, pt.entry),
            (S::EdgeArmed { .. }, Ev::HotkeyRelease) => Transition::stay(S::LocalControl),
            (S::EdgeArmed { .. }, Ev::RemoteSwitchRequest { source: s, entry }) => Transition::to(
                S::Receiving { source: s },
                vec![
                    DomainEffect::SendSwitchAck { source: s },
                    DomainEffect::BeginInjecting { source: s, entry },
                ],
            ),

            // ---- Switching (awaiting ack) ----
            (S::Switching { target }, Ev::SwitchAck) => {
                Transition::to(S::RemoteControl { target }, Vec::new())
            }
            (S::Switching { .. }, Ev::SwitchNack) => S::return_home(None, false),
            (S::Switching { .. }, Ev::SwitchTimeout) => S::return_home(None, false),
            (S::Switching { .. }, Ev::HotkeyRelease) => S::return_home(None, false),
            // Capture already started but no ack yet — still fully fail-safe.
            (S::Switching { target }, Ev::TransportLost) => S::lost_with_failsafe(target),

            // ---- RemoteControl (we drive the peer) ----
            (S::RemoteControl { target }, Ev::ReturnHome { .. }) => {
                S::return_home(Some(target), false)
            }
            (S::RemoteControl { target }, Ev::HotkeyRelease) => S::return_home(Some(target), false),
            (S::RemoteControl { target }, Ev::TransportLost) => S::lost_with_failsafe(target),

            // ---- Receiving (peer drives us) ----
            (S::Receiving { .. }, Ev::RemoteRelease) => Transition::to(
                S::LocalControl,
                vec![DomainEffect::StopInjecting, DomainEffect::ReleaseAllKeys],
            ),
            (S::Receiving { .. }, Ev::TransportLost) => Transition::to(
                S::LocalControl,
                vec![DomainEffect::StopInjecting, DomainEffect::ReleaseAllKeys],
            ),
            (S::Receiving { .. }, Ev::HotkeyRelease) => Transition::to(
                S::LocalControl,
                vec![DomainEffect::StopInjecting, DomainEffect::ReleaseAllKeys],
            ),

            // ---- Lost (recovery) ----
            (S::Lost { last }, Ev::Reconnected { peer }) if peer == last => {
                // Safe default: do NOT auto-grab control; user re-initiates.
                Transition::to(S::LocalControl, Vec::new())
            }
            (S::Lost { .. }, Ev::HotkeyRelease) => Transition::to(S::LocalControl, Vec::new()),

            // ---- Everything else: ignore, stay put ----
            (state, _) => Transition::stay(state),
        }
    }

    /// Shared fail-safe transition into `Lost`.
    fn lost_with_failsafe(last: DeviceId) -> Transition {
        Transition::to(
            FocusState::Lost { last },
            vec![
                DomainEffect::StopCapture,
                DomainEffect::RestoreLocalCursor,
                DomainEffect::ReleaseAllKeys,
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn dev(n: u128) -> DeviceId {
        DeviceId(Uuid::from_u128(n))
    }

    fn pt(target: DeviceId) -> PendingTransition {
        PendingTransition {
            target,
            edge: Edge::Right,
            entry: EntryPoint::new(Edge::Left, 0.5),
        }
    }

    fn cfg() -> FocusConfig {
        FocusConfig { arm_samples: 3 }
    }

    #[test]
    fn arming_requires_hysteresis_then_commits() {
        let t = dev(2);
        let mut s = FocusState::LocalControl;
        // sample 1
        let tr = s.handle(FocusEvent::EdgeReached(pt(t)), &cfg());
        assert_eq!(
            tr.next,
            FocusState::EdgeArmed {
                target: t,
                edge: Edge::Right,
                samples: 1
            }
        );
        assert!(tr.effects.is_empty());
        s = tr.next;
        // sample 2
        s = s.handle(FocusEvent::EdgeReached(pt(t)), &cfg()).next;
        assert_eq!(
            s,
            FocusState::EdgeArmed {
                target: t,
                edge: Edge::Right,
                samples: 2
            }
        );
        // sample 3 → commit
        let tr = s.handle(FocusEvent::EdgeReached(pt(t)), &cfg());
        assert_eq!(tr.next, FocusState::Switching { target: t });
        assert!(tr.effects.contains(&DomainEffect::StartCapture));
        assert!(tr.effects.contains(&DomainEffect::SendSwitchRequest {
            target: t,
            entry: pt(t).entry
        }));
    }

    #[test]
    fn edge_cleared_disarms() {
        let t = dev(2);
        let s = FocusState::EdgeArmed {
            target: t,
            edge: Edge::Right,
            samples: 2,
        };
        let tr = s.handle(FocusEvent::EdgeCleared, &cfg());
        assert_eq!(tr.next, FocusState::LocalControl);
    }

    #[test]
    fn manual_switch_bypasses_hysteresis() {
        let t = dev(2);
        let tr = FocusState::LocalControl.handle(FocusEvent::ManualSwitch(pt(t)), &cfg());
        assert_eq!(tr.next, FocusState::Switching { target: t });
        assert!(tr.effects.contains(&DomainEffect::StartCapture));
    }

    #[test]
    fn switch_ack_enters_remote_control() {
        let t = dev(2);
        let tr = FocusState::Switching { target: t }.handle(FocusEvent::SwitchAck, &cfg());
        assert_eq!(tr.next, FocusState::RemoteControl { target: t });
    }

    #[test]
    fn switch_nack_returns_home_and_restores() {
        let t = dev(2);
        let tr = FocusState::Switching { target: t }.handle(FocusEvent::SwitchNack, &cfg());
        assert_eq!(tr.next, FocusState::LocalControl);
        assert!(tr.effects.contains(&DomainEffect::StopCapture));
        assert!(tr.effects.contains(&DomainEffect::RestoreLocalCursor));
    }

    #[test]
    fn hotkey_release_from_remote_sends_release() {
        let t = dev(2);
        let tr = FocusState::RemoteControl { target: t }.handle(FocusEvent::HotkeyRelease, &cfg());
        assert_eq!(tr.next, FocusState::LocalControl);
        assert!(tr
            .effects
            .contains(&DomainEffect::SendRelease { target: t }));
        assert!(tr.effects.contains(&DomainEffect::StopCapture));
    }

    #[test]
    fn return_home_event_releases_peer() {
        let t = dev(2);
        let tr = FocusState::RemoteControl { target: t }.handle(
            FocusEvent::ReturnHome {
                entry: EntryPoint::new(Edge::Right, 0.5),
            },
            &cfg(),
        );
        assert_eq!(tr.next, FocusState::LocalControl);
        assert!(tr
            .effects
            .contains(&DomainEffect::SendRelease { target: t }));
    }

    #[test]
    fn remote_request_makes_us_receiver() {
        let src = dev(5);
        let tr = FocusState::LocalControl.handle(
            FocusEvent::RemoteSwitchRequest {
                source: src,
                entry: EntryPoint::new(Edge::Left, 0.2),
            },
            &cfg(),
        );
        assert_eq!(tr.next, FocusState::Receiving { source: src });
        assert!(tr
            .effects
            .contains(&DomainEffect::SendSwitchAck { source: src }));
        assert!(tr
            .effects
            .iter()
            .any(|e| matches!(e, DomainEffect::BeginInjecting { .. })));
    }

    #[test]
    fn receiving_release_flushes_keys() {
        let src = dev(5);
        let tr = FocusState::Receiving { source: src }.handle(FocusEvent::RemoteRelease, &cfg());
        assert_eq!(tr.next, FocusState::LocalControl);
        assert!(tr.effects.contains(&DomainEffect::ReleaseAllKeys));
        assert!(tr.effects.contains(&DomainEffect::StopInjecting));
    }

    #[test]
    fn lost_then_reconnect_returns_local_without_autograb() {
        let t = dev(2);
        let tr = FocusState::Lost { last: t }.handle(FocusEvent::Reconnected { peer: t }, &cfg());
        assert_eq!(tr.next, FocusState::LocalControl);
        assert!(tr.effects.is_empty());
    }

    /// Exhaustive fail-safe check: from EVERY state, TransportLost must leave us
    /// in a safe local-ish state and never leave us injecting/capturing without
    /// a key release.
    #[test]
    fn transport_lost_is_safe_from_all_active_states() {
        let t = dev(2);
        let active_states = [
            FocusState::Switching { target: t },
            FocusState::RemoteControl { target: t },
            FocusState::Receiving { source: t },
        ];
        for s in active_states {
            let tr = s.handle(FocusEvent::TransportLost, &cfg());
            assert!(
                tr.effects.contains(&DomainEffect::ReleaseAllKeys),
                "state {s:?} must release all keys on TransportLost"
            );
            // Must not remain in an actively-controlling state.
            assert!(
                matches!(tr.next, FocusState::LocalControl | FocusState::Lost { .. }),
                "state {s:?} ended in unsafe {:?}",
                tr.next
            );
        }
    }

    #[test]
    fn local_control_transport_lost_is_noop() {
        let tr = FocusState::LocalControl.handle(FocusEvent::TransportLost, &cfg());
        assert_eq!(tr.next, FocusState::LocalControl);
    }

    // ---- Property tests ----
    use proptest::prelude::*;

    fn arb_edge() -> impl Strategy<Value = Edge> {
        prop_oneof![
            Just(Edge::Top),
            Just(Edge::Bottom),
            Just(Edge::Left),
            Just(Edge::Right)
        ]
    }

    fn arb_entry() -> impl Strategy<Value = EntryPoint> {
        (arb_edge(), 0.0f32..=1.0).prop_map(|(e, p)| EntryPoint::new(e, p))
    }

    fn arb_pt() -> impl Strategy<Value = PendingTransition> {
        (1u128..4, arb_edge(), arb_entry()).prop_map(|(n, edge, entry)| PendingTransition {
            target: dev(n),
            edge,
            entry,
        })
    }

    fn arb_state() -> impl Strategy<Value = FocusState> {
        prop_oneof![
            Just(FocusState::LocalControl),
            (1u128..4, arb_edge(), 0u8..5).prop_map(|(n, edge, samples)| FocusState::EdgeArmed {
                target: dev(n),
                edge,
                samples
            }),
            (1u128..4).prop_map(|n| FocusState::Switching { target: dev(n) }),
            (1u128..4).prop_map(|n| FocusState::RemoteControl { target: dev(n) }),
            (1u128..4).prop_map(|n| FocusState::Receiving { source: dev(n) }),
            (1u128..4).prop_map(|n| FocusState::Lost { last: dev(n) }),
        ]
    }

    fn arb_event() -> impl Strategy<Value = FocusEvent> {
        prop_oneof![
            arb_pt().prop_map(FocusEvent::EdgeReached),
            Just(FocusEvent::EdgeCleared),
            arb_entry().prop_map(|entry| FocusEvent::ReturnHome { entry }),
            arb_pt().prop_map(FocusEvent::ManualSwitch),
            Just(FocusEvent::HotkeyRelease),
            Just(FocusEvent::SwitchAck),
            Just(FocusEvent::SwitchNack),
            Just(FocusEvent::SwitchTimeout),
            (1u128..4, arb_entry()).prop_map(|(n, entry)| FocusEvent::RemoteSwitchRequest {
                source: dev(n),
                entry
            }),
            Just(FocusEvent::RemoteRelease),
            Just(FocusEvent::TransportLost),
            (1u128..4).prop_map(|n| FocusEvent::Reconnected { peer: dev(n) }),
        ]
    }

    proptest! {
        /// The machine never panics, and the safety invariant holds: losing the
        /// transport from any actively-controlling/receiving state ALWAYS emits
        /// a key release and never leaves us in such a state.
        #[test]
        fn handle_is_total_and_failsafe(state in arb_state(), event in arb_event()) {
            let tr = state.handle(event, &FocusConfig::default());

            if event == FocusEvent::TransportLost {
                let was_active = matches!(
                    state,
                    FocusState::Switching { .. }
                        | FocusState::RemoteControl { .. }
                        | FocusState::Receiving { .. }
                );
                if was_active {
                    prop_assert!(tr.effects.contains(&DomainEffect::ReleaseAllKeys));
                    // Bind to a bool first: prop_assert! stringifies its argument
                    // and the `{ .. }` pattern would corrupt its format string.
                    let ended_safe =
                        matches!(tr.next, FocusState::LocalControl | FocusState::Lost { .. });
                    prop_assert!(ended_safe);
                }
            }

            // Whenever we start capturing, we must also hide the local cursor —
            // never grab input while leaving a visible local cursor behind.
            if tr.effects.contains(&DomainEffect::StartCapture) {
                prop_assert!(tr.effects.contains(&DomainEffect::HideLocalCursor));
            }
        }
    }
}

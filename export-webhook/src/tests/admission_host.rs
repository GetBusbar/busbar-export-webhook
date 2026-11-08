// SPDX-License-Identifier: Apache-2.0
//! A fixed need.admit answer for tests of the webhook's discovery state.
use busbar_contract::abi::host::service::{HostSlots, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};

pub struct AdmissionHost {
    slots: Box<HostSlots>,
    tables: HostTables,
}
extern "C" fn admit(ctx: HostCtx, _: *const std::ffi::c_void, out: *mut ServiceOut) -> RawOutcome {
    let outcome = match ctx.handle {
        1 => Outcome::Ready,
        2 => Outcome::Failed,
        _ => Outcome::Refused,
    };
    let raw = RawOutcome::of(outcome);
    // SAFETY: the SDK supplies a writable ServiceOut for this synchronous need.admit call.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            error: if outcome == Outcome::Refused {
                AbiStr::of("destination refused")
            } else {
                AbiStr::ZERO
            },
            ..ServiceOut::ZERO
        });
    }
    raw
}
impl AdmissionHost {
    pub fn new(outcome: Outcome) -> Self {
        // SAFETY: HostSlots contains integers and nullable function pointers; zero is valid.
        let mut slots: Box<HostSlots> = Box::new(unsafe { std::mem::zeroed() });
        slots.size = std::mem::size_of::<HostSlots>() as u32;
        slots.slots = busbar_contract::abi::host::service::SERVICES;
        slots.need_admit = Some(admit);
        let tables = HostTables {
            size: std::mem::size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx {
                handle: match outcome {
                    Outcome::Ready => 1,
                    Outcome::Failed => 2,
                    _ => 3,
                },
            },
            wake: None,
            conns: std::ptr::null(),
            services: slots.as_ref(),
            io: std::ptr::null(),
        };
        Self { slots, tables }
    }
    pub fn host(
        &self,
    ) -> busbar_contract::abi::sdk::conn::Host<busbar_contract::plugin::markers::ExportKind> {
        let _ = &self.slots;
        // SAFETY: the owned table prefixes are readable here; Host copies their slots.
        // The sole callback is static and its context is a fixed scalar, not borrowed state.
        unsafe { busbar_contract::abi::sdk::conn::Host::test_from_raw(&self.tables) }
    }
}

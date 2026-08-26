//! Offline qualifier for dangerous fan-control and lifecycle fault orderings.
//!
//! These suites are deliberately gathered into one test target so qualification can exercise the
//! complete matrix without touching host hwmon endpoints, services, or runtime locks. Every module
//! below drives the public control boundary exclusively through [`fan_control_core::FakePlatform`]
//! or a wrapper around it.
//!
//! Coverage is intentionally assembled at the prerequisite-suite boundary:
//! - `runtime_faults`: sensor, identity, partial-mode, write/readback, tachometer, interference,
//!   disappearance, permanent latch, and no-post-fault-demand orderings;
//! - `ownership_faults`: competing-controller and uncertain-ownership admission failures;
//! - `arming_faults`: pre-handover identity, mode, write/readback, tachometer, interference,
//!   restoration, and containment failures;
//! - `restoration_faults`: independent two-fan Auto attempts and partial/failed confirmation;
//! - `containment_faults`: failed Auto restoration and per-fan emergency containment.

// Each pre-existing integration suite owns its private support module. Keeping those suites intact
// is what makes this target a faithful aggregate of the independently runnable prerequisites.
#![allow(clippy::duplicate_mod)]

#[path = "controller_ownership.rs"]
mod ownership_faults;

#[path = "safe_arming.rs"]
mod arming_faults;

#[path = "firmware_auto_restoration.rs"]
mod restoration_faults;

#[path = "healthy_control_cycle.rs"]
mod runtime_faults;

#[path = "emergency_containment.rs"]
mod containment_faults;

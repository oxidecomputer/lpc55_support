// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! A measurement token tells the SP that it has been measured
//!
//! For various reasons (see RFD 568), the RoT is not allowed to proactively
//! reset the SP; it can only catch the SP during a reset and hold it for
//! measurements.  However, during initial power-on, the SP boots faster than
//! the RoT.  What are we to do?
//!
//! RFD 568 proposes a coordination mechanism: the SP will reset itself a few
//! times, until either a retry count is exceeded or it boots with a token
//! deposited in a particular memory location (indicating that it has been
//! measured).
//!
//! This crate defines constants to implement this coordination mechanism.
//! These constants are shared between the RoT `SpCtrl` task, the SP's kernel,
//! and the Humility debugger.
//!
//! The 32-bit values are chosen arbitrarily from hashes of sentences; we just
//! need something that's not likely to be in RAM by accident.
#![no_std]

/// Address at which the measurement token can be found
///
/// This is DTCM RAM on the STM32H7, which is not used by any of our production
/// firmware.  In Hubris, the kernel build script is responsible for ensuring
/// that this memory is available.
pub const SP_ADDR: *mut u32 = 0x2000_0000 as *mut u32;

/// A valid measurement has been made and booting can continue
///
/// This value should only be written by the RoT
pub const VALID: u32 = 0xc887a12;

/// No measurement has been made, but booting should continue
///
/// This value is written by an attached debugger, which otherwise prevents
/// measurements because it's attached the SWD port.
pub const SKIP: u32 = 0x9f38bd71;

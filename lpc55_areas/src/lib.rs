// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Debug;

use packed_struct::prelude::*;
use packed_struct::PackingError;
use serde::{Deserialize, Serialize};

// Table 183, section 7.3.4
#[derive(PrimitiveEnum, Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootImageType {
    PlainImage = 0x0,
    SignedImage = 0x4,
    CRCImage = 0x5,
}

#[derive(PrimitiveEnum, Copy, Clone, Debug, Eq, PartialEq)]
pub enum TzmImageType {
    Enabled = 0x0,
    Disabled = 0x1,
}

// Table 192
#[derive(PrimitiveEnum, Copy, Clone, Debug, Eq, PartialEq)]
pub enum TzmPreset {
    NotPresent = 0x0,
    Present = 0x1,
}

#[derive(Debug, PackedStruct)]
#[packed_struct(size_bytes = "4", bit_numbering = "msb0")]
pub struct BootField {
    #[packed_field(ty = "enum", bits = "0..8")]
    pub img_type: EnumCatchAll<BootImageType>,
    #[packed_field(ty = "enum", bits = "13")]
    pub tzm_preset: TzmPreset,
    #[packed_field(ty = "enum", bits = "14")]
    pub tzm_image_type: TzmImageType,
}

impl BootField {
    pub fn new(image_type: BootImageType) -> BootField {
        // Table 183, section 7.3.4 for the magic numbers
        BootField {
            tzm_image_type: TzmImageType::Enabled,
            tzm_preset: TzmPreset::NotPresent,
            img_type: image_type.into(),
        }
    }
}

// We designate bit 0 for DFLT and bit 1 for PIN
#[derive(PrimitiveEnum, Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[repr(u32)]
pub enum DebugFieldSetting {
    AlwaysEnabled = 0b11,
    DebugAuth = 0b00,
    AlwaysDisabled = 0b10,
}

impl DebugFieldSetting {
    fn always_enabled() -> Self {
        Self::AlwaysEnabled
    }

    fn dflt(&self) -> bool {
        ((*self as u32) & 1) == 1
    }

    fn pin(&self) -> bool {
        (((*self as u32) & 2) >> 1) == 1
    }

    fn debug_cred_socu(&self) -> bool {
        *self == DebugFieldSetting::DebugAuth
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DebugSettings {
    // The matrix of debug settings for CPU0
    #[serde(default = "DebugFieldSetting::always_enabled")]
    pub non_invasive_debug: DebugFieldSetting,
    #[serde(default = "DebugFieldSetting::always_enabled")]
    pub invasive_debug: DebugFieldSetting,
    #[serde(default = "DebugFieldSetting::always_enabled")]
    pub secure_non_invasive_debug: DebugFieldSetting,
    #[serde(default = "DebugFieldSetting::always_enabled")]
    pub secure_invasive_debug: DebugFieldSetting,
    // JTAG/TAP access
    #[serde(default = "DebugFieldSetting::always_enabled")]
    pub tap_enable: DebugFieldSetting,
    // CPU1 debugging
    #[serde(default = "DebugFieldSetting::always_enabled")]
    pub cpu1_dbg_enable: DebugFieldSetting,
    // ISP allowed via debug mailbox
    #[serde(default = "DebugFieldSetting::always_enabled")]
    pub isp_enable: DebugFieldSetting,
    // fault analysis/mass erase enable
    #[serde(default = "DebugFieldSetting::always_enabled")]
    pub fa_me_enable: DebugFieldSetting,
    // CPU1 non-invasive debugging
    #[serde(default = "DebugFieldSetting::always_enabled")]
    pub cpu1_non_invasive_enable: DebugFieldSetting,
    // require exact UUID match
    #[serde(default)]
    pub uuid_check: bool,
}

impl DebugSettings {
    pub fn new() -> Self {
        DebugSettings {
            non_invasive_debug: DebugFieldSetting::AlwaysEnabled,
            invasive_debug: DebugFieldSetting::AlwaysEnabled,
            secure_non_invasive_debug: DebugFieldSetting::AlwaysEnabled,
            secure_invasive_debug: DebugFieldSetting::AlwaysEnabled,
            tap_enable: DebugFieldSetting::AlwaysEnabled,
            cpu1_dbg_enable: DebugFieldSetting::AlwaysEnabled,
            isp_enable: DebugFieldSetting::AlwaysEnabled,
            fa_me_enable: DebugFieldSetting::AlwaysEnabled,
            cpu1_non_invasive_enable: DebugFieldSetting::AlwaysEnabled,
            uuid_check: false,
        }
    }

    pub fn pin(&self) -> u32 {
        let mut pin = CCSOCUPin(0);

        pin.set_non_invasive_debug(self.non_invasive_debug.pin());
        pin.set_invasive_debug(self.invasive_debug.pin());
        pin.set_secure_invasive_debug(self.secure_invasive_debug.pin());
        pin.set_secure_non_invasive_debug(self.secure_non_invasive_debug.pin());
        pin.set_tap_enable(self.tap_enable.pin());
        pin.set_cpu1_dbg_enable(self.cpu1_dbg_enable.pin());
        pin.set_isp_enable(self.isp_enable.pin());
        pin.set_fa_me_enable(self.fa_me_enable.pin());
        pin.set_cpu1_non_invasive_enable(self.cpu1_non_invasive_enable.pin());
        pin.set_uuid_check(self.uuid_check);

        pin.invert_field()
    }

    pub fn dflt(&self) -> u32 {
        let mut dflt = CCSOCUDflt(0);

        dflt.set_non_invasive_debug(self.non_invasive_debug.dflt());
        dflt.set_invasive_debug(self.invasive_debug.dflt());
        dflt.set_secure_invasive_debug(self.secure_invasive_debug.dflt());
        dflt.set_secure_non_invasive_debug(self.secure_non_invasive_debug.dflt());
        dflt.set_tap_enable(self.tap_enable.dflt());
        dflt.set_cpu1_dbg_enable(self.cpu1_dbg_enable.dflt());
        dflt.set_isp_enable(self.isp_enable.dflt());
        dflt.set_fa_me_enable(self.fa_me_enable.dflt());
        dflt.set_cpu1_non_invasive_enable(self.cpu1_non_invasive_enable.dflt());

        dflt.invert_field()
    }

    pub fn debug_cred_socu(&self) -> u32 {
        let mut dflt = CCSOCUDflt(0);

        dflt.set_non_invasive_debug(self.non_invasive_debug.debug_cred_socu());
        dflt.set_invasive_debug(self.invasive_debug.debug_cred_socu());
        dflt.set_secure_invasive_debug(self.secure_invasive_debug.debug_cred_socu());
        dflt.set_secure_non_invasive_debug(self.secure_non_invasive_debug.debug_cred_socu());
        dflt.set_tap_enable(self.tap_enable.debug_cred_socu());
        dflt.set_cpu1_dbg_enable(self.cpu1_dbg_enable.debug_cred_socu());
        dflt.set_isp_enable(self.isp_enable.debug_cred_socu());
        dflt.set_fa_me_enable(self.fa_me_enable.debug_cred_socu());
        dflt.set_cpu1_non_invasive_enable(self.cpu1_non_invasive_enable.debug_cred_socu());

        dflt.0 & 0xffff
    }
}

impl Default for DebugSettings {
    fn default() -> Self {
        Self::new()
    }
}

bitfield::bitfield! {
    pub struct CCSOCUPin(u32);
    impl Debug;
    pub non_invasive_debug, set_non_invasive_debug: 0;
    pub invasive_debug, set_invasive_debug: 1;
    pub secure_non_invasive_debug, set_secure_non_invasive_debug: 2;
    pub secure_invasive_debug, set_secure_invasive_debug: 3;
    pub tap_enable, set_tap_enable: 4;
    pub cpu1_dbg_enable, set_cpu1_dbg_enable: 5;
    pub isp_enable, set_isp_enable: 6;
    pub fa_me_enable, set_fa_me_enable: 7;
    pub cpu1_non_invasive_enable, set_cpu1_non_invasive_enable: 9;
    pub uuid_check, set_uuid_check: 15;
}

impl CCSOCUPin {
    pub fn invert_field(&self) -> u32 {
        let bottom = self.0 & 0xffff;
        (!bottom << 16) | bottom
    }
}

bitfield::bitfield! {
    pub struct CCSOCUDflt(u32);
    impl Debug;
    pub non_invasive_debug, set_non_invasive_debug: 0;
    pub invasive_debug, set_invasive_debug: 1;
    pub secure_non_invasive_debug, set_secure_non_invasive_debug: 2;
    pub secure_invasive_debug, set_secure_invasive_debug: 3;
    pub tap_enable, set_tap_enable: 4;
    pub cpu1_dbg_enable, set_cpu1_dbg_enable: 5;
    pub isp_enable, set_isp_enable: 6;
    pub fa_me_enable, set_fa_me_enable: 7;
    pub cpu1_non_invasive_enable, set_cpu1_non_invasive_enable: 9;
}

impl CCSOCUDflt {
    pub fn invert_field(&self) -> u32 {
        let bottom = self.0 & 0xffff;
        (!bottom << 16) | bottom
    }
}

// Enums for the fields in SECURE_BOOT_CFG
// Most of these fields have duplicates and should all do the same thing
// according to the documentation

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum RSA4KStatus {
    RSA2048Keys = 0x0,
    RSA4096Only1 = 0x1,
    RSA4096Only2 = 0x2,
    RSA4096Only3 = 0x3,
}

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum DiceNXPIncStatus {
    NotIncluded = 0x0,
    Included1 = 0x01,
    Included2 = 0x02,
    Included3 = 0x03,
}

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum DiceCustIncStatus {
    NotIncluded = 0x0,
    Included1 = 0x01,
    Included2 = 0x02,
    Included3 = 0x03,
}

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum EnableDiceStatus {
    EnableDice = 0x0,
    DisableDice1 = 0x1,
    DisableDice2 = 0x2,
    DisableDice3 = 0x3,
}

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum DiceIncSecEpoch {
    NotIncluded = 0x0,
    Included1 = 0x1,
    Included2 = 0x2,
    Included3 = 0x3,
}

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum TZMImageStatus {
    InImageHeader = 0x0,
    DisableTZM = 0x1,
    EnableTZM = 0x2,
    PresetTZM = 0x3,
}

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum SetKeyStatus {
    EnableKeyCode = 0x0,
    BlockKeyCode1 = 0x1,
    BlockKeyCode2 = 0x2,
    BlockKeyCode3 = 0x3,
}

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum EnrollStatus {
    EnableEnroll = 0x0,
    BlockEnroll1 = 0x1,
    BlockEnroll2 = 0x2,
    BlockEnroll3 = 0x3,
}

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum SecBootStatus {
    PlainImage = 0x0,
    SignedImage1 = 0x1,
    SignedImage2 = 0x2,
    SignedImage3 = 0x3,
}

/// `SECURE_BOOT_CFG` configuration word (`0x3E41C`)
#[derive(Debug, Clone, PackedStruct)]
#[packed_struct(size_bytes = "4", endian = "lsb", bit_numbering = "lsb0")]
pub struct SecureBootCfg {
    /// Can force boot to 4096 bit keys only
    #[packed_field(ty = "enum", bits = "0..=1")]
    pub rsa4k: RSA4KStatus,

    /// Include NXP area in DICE calculation
    #[packed_field(ty = "enum", bits = "2..=3")]
    pub dice_inc_nxp_cfg: DiceNXPIncStatus,

    /// Inlcude Customer area in DICE calculation
    #[packed_field(ty = "enum", bits = "4..=5")]
    pub dice_cust_cfg: DiceCustIncStatus,

    /// Enable DICE
    #[packed_field(ty = "enum", bits = "6..=7")]
    pub skip_dice: EnableDiceStatus,

    /// Choose TZ image type. Similar to the field that's in the image at 0x24
    /// See also why the default is to just use what's in the image
    #[packed_field(ty = "enum", bits = "8..=9")]
    pub tzm_image_type: TZMImageStatus,

    /// Block SetKey PUF operation
    #[packed_field(ty = "enum", bits = "10..=11")]
    pub block_set_key: SetKeyStatus,

    /// Block EnrollKey Operationg
    #[packed_field(ty = "enum", bits = "12..=13")]
    pub block_enroll: EnrollStatus,

    /// Undocumented?
    #[packed_field(ty = "enum", bits = "14..=15")]
    pub dice_inc_sec_epoch: DiceIncSecEpoch,

    #[packed_field(bits = "29..=16")]
    _reserved: ReservedZero<packed_bits::Bits<14>>,

    /// Enable secure boot
    #[packed_field(ty = "enum", bits = "30..=31")]
    pub sec_boot_en: SecBootStatus,
}

impl SecureBootCfg {
    pub fn new() -> SecureBootCfg {
        SecureBootCfg {
            rsa4k: RSA4KStatus::RSA2048Keys,
            dice_inc_nxp_cfg: DiceNXPIncStatus::NotIncluded,
            dice_cust_cfg: DiceCustIncStatus::NotIncluded,
            skip_dice: EnableDiceStatus::EnableDice,
            tzm_image_type: TZMImageStatus::InImageHeader,
            block_set_key: SetKeyStatus::EnableKeyCode,
            block_enroll: EnrollStatus::EnableEnroll,
            dice_inc_sec_epoch: DiceIncSecEpoch::NotIncluded,
            _reserved: ReservedZero::<packed_bits::Bits<14>>::default(),
            sec_boot_en: SecBootStatus::PlainImage,
        }
    }
}

impl SecureBootCfg {
    pub fn set_dice(&mut self, use_dice: bool) {
        if use_dice {
            self.skip_dice = EnableDiceStatus::EnableDice;
        } else {
            self.skip_dice = EnableDiceStatus::DisableDice1;
        }
    }

    pub fn set_dice_inc_nxp_cfg(&mut self, use_nxp_cfg: bool) {
        if use_nxp_cfg {
            self.dice_inc_nxp_cfg = DiceNXPIncStatus::Included1;
        }
    }

    pub fn set_dice_inc_cust_cfg(&mut self, use_cust_cfg: bool) {
        if use_cust_cfg {
            self.dice_cust_cfg = DiceCustIncStatus::Included1;
        }
    }

    pub fn set_dice_inc_sec_epoch(&mut self, inc_sec_epoch: bool) {
        if inc_sec_epoch {
            self.dice_inc_sec_epoch = DiceIncSecEpoch::Included1;
        }
    }

    pub fn set_sec_boot(&mut self, sec_boot: bool) {
        if sec_boot {
            self.sec_boot_en = SecBootStatus::SignedImage3;
        }
    }

    pub fn set_rsa_4k(&mut self, rsa4k: bool) {
        self.rsa4k = if rsa4k {
            RSA4KStatus::RSA4096Only1
        } else {
            RSA4KStatus::RSA2048Keys
        }
    }
}

impl Default for SecureBootCfg {
    fn default() -> Self {
        Self::new()
    }
}

// Fields omitted for those parts we really don't care about
#[derive(PrimitiveEnum, Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum DefaultIsp {
    Auto = 0b000,
    Uart = 0b010,
    Diabled = 0b111,
}

impl DefaultIsp {
    pub fn auto() -> Self {
        Self::Auto
    }
}

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum BootSpeed {
    Nmpa = 0b00,
    Fro48mhz = 0b10,
    Fro96mhz = 0b01,
}

/// Represents a pin on the LPC55 used to indicate an error during boot
#[derive(Copy, Clone, Debug)]
pub struct BootErrorPin {
    port: u8,
    pin: u8,
}

impl BootErrorPin {
    /// Returns `None` if the port or pin are invalid
    pub fn new(port: u8, pin: u8) -> Option<Self> {
        if port < 8 && pin < 32 {
            Some(Self { port, pin })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PackedStruct)]
#[packed_struct(size_bytes = "4", endian = "lsb", bit_numbering = "lsb0")]
pub struct BootCfg {
    #[packed_field(bits = "3..=0")]
    _reserved1: ReservedZero<packed_bits::Bits<4>>,

    // Default ISP mode, can later be enabled via debug auth
    #[packed_field(ty = "enum", bits = "4..=6")]
    pub default_isp: EnumCatchAll<DefaultIsp>,

    // Default setting for the main system clock
    #[packed_field(ty = "enum", bits = "7..=8")]
    pub boot_speed: EnumCatchAll<BootSpeed>,

    #[packed_field(bits = "23..=9")]
    _reserved: ReservedZero<packed_bits::Bits<15>>,

    #[packed_field(bits = "26..=24")]
    pub boot_port: u8,

    #[packed_field(bits = "31..=27")]
    pub boot_pin: u8,
}

impl BootCfg {
    pub fn new(default_isp: DefaultIsp, boot_speed: BootSpeed, boot_pin: BootErrorPin) -> Self {
        BootCfg {
            default_isp: packed_struct::EnumCatchAll::Enum(default_isp),
            boot_speed: packed_struct::EnumCatchAll::Enum(boot_speed),
            _reserved1: ReservedZero::<packed_bits::Bits<4>>::default(),
            _reserved: ReservedZero::<packed_bits::Bits<15>>::default(),
            boot_port: boot_pin.port,
            boot_pin: boot_pin.pin,
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, PackedStruct)]
#[packed_struct(size_bytes = "512", bit_numbering = "msb0", endian = "lsb")]
pub struct CMPAPage {
    // Features settings such as a boot failure pin, boot speed and
    // default ISP mode. Okay to leave at 0x0
    pub boot_cfg: u32,

    // Undocumented what this does
    pub spi_flash_cfg: u32,

    // Can set vendor/product ID
    pub usb_id: u32,

    // Undocumented what this does
    pub sdio_cfg: u32,

    // Can turn off various peripherals.
    pub cc_socu_pin: u32,

    pub cc_socu_dflt: u32,

    // Related to secure debug
    pub vendor_usage: u32,

    // Sets boot mode
    pub secure_boot_cfg: u32,

    // prince settings
    pub prince_base_addr: u32,
    pub prince_sr_0: u32,
    pub prince_sr_1: u32,
    pub prince_sr_2: u32,

    // These are listed in the manual but not documented at all
    pub xtal_32khz_capabank_trim: u32,
    pub xtal_16khz_capabank_trim: u32,

    pub flash_remap_size: u32,

    pub blank1: [u8; 0x14],

    // The hash of the RoT keys
    pub rotkh: [u8; 32],

    // For debugging we split up the blank area
    pub blank2: [u8; 32],
    pub blank3: [u8; 32],
    pub blank4: [u8; 32],
    pub blank5: [u8; 32],
    pub blank6: [u8; 16],
    pub customer_defined0: [u8; 32],
    pub customer_defined1: [u8; 32],
    pub customer_defined2: [u8; 32],
    pub customer_defined3: [u8; 32],
    pub customer_defined4: [u8; 32],
    pub customer_defined5: [u8; 32],
    pub customer_defined6: [u8; 32],
    // !!! DO NOT WRITE THIS !!!
    // This will prevent re-writing!
    pub sha256_digest: [u8; 32],
}

impl CMPAPage {
    pub fn new() -> Self {
        CMPAPage {
            ..Default::default()
        }
    }

    pub fn set_debug_fields(&mut self, settings: DebugSettings) -> Result<(), PackingError> {
        self.cc_socu_pin = settings.pin();
        self.cc_socu_dflt = settings.dflt();
        Ok(())
    }

    pub fn get_cc_socu_pin(&self) -> Result<CCSOCUPin, PackingError> {
        Ok(CCSOCUPin(self.cc_socu_pin))
    }

    pub fn get_cc_socu_dflt(&self) -> Result<CCSOCUDflt, PackingError> {
        Ok(CCSOCUDflt(self.cc_socu_dflt))
    }

    // We're very deliberate about using from_be_bytes here despite
    // the fact that this is technically going to be an le integer.
    // packed_struct does not handle endian byte swapping for structres
    // and the spreadsheet given by NXP gives everything in little
    // endian form. Many other fields in the structure are marked
    // little endian so to avoid a double endian swap here we store
    // the integer as big endian and let the pack() function swap the
    // endian for us.

    pub fn set_secure_boot_cfg(&mut self, sec_boot_cfg: SecureBootCfg) -> Result<(), PackingError> {
        self.secure_boot_cfg = u32::from_be_bytes(sec_boot_cfg.pack()?);
        Ok(())
    }

    pub fn get_secure_boot_cfg(&self) -> Result<SecureBootCfg, PackingError> {
        SecureBootCfg::unpack(&self.secure_boot_cfg.to_be_bytes())
    }

    pub fn set_boot_cfg(
        &mut self,
        default_isp: DefaultIsp,
        boot_speed: BootSpeed,
        boot_pin: BootErrorPin,
    ) -> Result<(), PackingError> {
        let cfg = BootCfg::new(default_isp, boot_speed, boot_pin);
        self.boot_cfg = u32::from_be_bytes(cfg.pack()?);
        Ok(())
    }

    pub fn get_boot_cfg(&self) -> Result<BootCfg, PackingError> {
        BootCfg::unpack(&self.boot_cfg.to_be_bytes())
    }

    pub fn set_rotkh(&mut self, rotkh: &[u8; 32]) {
        self.rotkh.clone_from_slice(rotkh);
    }

    pub fn to_vec(&mut self) -> Result<Vec<u8>, PackingError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.pack()?);
        Ok(bytes)
    }

    pub fn from_bytes(b: &[u8; 512]) -> Result<Self, PackingError> {
        let s = Self::unpack(b)?;
        Ok(s)
    }
}

#[derive(Clone, Debug, PackedStruct)]
#[repr(C)]
#[packed_struct(size_bytes = "0x20", bit_numbering = "msb0", endian = "msb")]
pub struct CertHeader {
    pub signature: [u8; 4],
    #[packed_field(endian = "lsb")]
    pub header_version: u32,
    #[packed_field(endian = "lsb")]
    pub header_length: u32,
    #[packed_field(endian = "lsb")]
    pub flags: u32,
    #[packed_field(endian = "lsb")]
    pub build_number: u32,
    #[packed_field(endian = "lsb")]
    pub total_image_len: u32,
    #[packed_field(endian = "lsb")]
    pub certificate_count: u32,
    #[packed_field(endian = "lsb")]
    pub certificate_table_len: u32,
}

impl CertHeader {
    pub fn new(cert_header_size: usize, cert_table_len: usize) -> CertHeader {
        CertHeader {
            // This 'signature' is just a simple marker
            signature: *b"cert",
            header_version: 1,
            header_length: cert_header_size as u32,
            // Need to be 0 for now
            flags: 0,
            build_number: 1,
            // The certificate table length is included in the total length so it
            // gets calculated aftewards
            total_image_len: 0,
            certificate_count: 1,
            // This is the total length of all certificates (plus padding)
            // Plus 4 bytes to store the x509 certificate length
            certificate_table_len: cert_table_len as u32,
        }
    }
}

#[derive(PrimitiveEnum, Copy, Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ROTKeyStatus {
    Invalid = 0x0,
    Enabled = 0x1,
    Revoked1 = 0x2,
    Revoked2 = 0x3,
}

impl ROTKeyStatus {
    pub fn invalid() -> Self {
        Self::Invalid
    }

    pub fn enabled() -> Self {
        Self::Enabled
    }
}

#[derive(Clone, Debug, PackedStruct)]
#[repr(C)]
#[packed_struct(size_bytes = "4", endian = "lsb", bit_numbering = "lsb0")]
pub struct RKTHRevoke {
    #[packed_field(ty = "enum", bits = "1..=0")]
    pub rotk0: ROTKeyStatus,

    #[packed_field(ty = "enum", bits = "3..=2")]
    pub rotk1: ROTKeyStatus,

    #[packed_field(ty = "enum", bits = "5..=4")]
    pub rotk2: ROTKeyStatus,

    #[packed_field(ty = "enum", bits = "7..=6")]
    pub rotk3: ROTKeyStatus,

    #[packed_field(bits = "31..=8")]
    _reserved: ReservedZero<packed_bits::Bits<24>>,
}

impl RKTHRevoke {
    pub fn new() -> RKTHRevoke {
        RKTHRevoke {
            rotk0: ROTKeyStatus::Invalid,
            rotk1: ROTKeyStatus::Invalid,
            rotk2: ROTKeyStatus::Invalid,
            rotk3: ROTKeyStatus::Invalid,
            _reserved: ReservedZero::<packed_bits::Bits<24>>::default(),
        }
    }

    pub fn enable_keys(&mut self, key0: bool, key1: bool, key2: bool, key3: bool) {
        if key0 {
            self.rotk0 = ROTKeyStatus::Enabled;
        }

        if key1 {
            self.rotk1 = ROTKeyStatus::Enabled;
        }

        if key2 {
            self.rotk2 = ROTKeyStatus::Enabled;
        }

        if key3 {
            self.rotk3 = ROTKeyStatus::Enabled;
        }
    }

    pub fn revoke_keys(&mut self, key0: bool, key1: bool, key2: bool, key3: bool) {
        if key0 {
            self.rotk0 = ROTKeyStatus::Revoked2;
        }

        if key1 {
            self.rotk1 = ROTKeyStatus::Revoked2;
        }

        if key2 {
            self.rotk2 = ROTKeyStatus::Revoked2;
        }

        if key3 {
            self.rotk3 = ROTKeyStatus::Revoked2;
        }
    }
}

impl Default for RKTHRevoke {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PackedStruct, Default)]
#[repr(C)]
#[packed_struct(size_bytes = "512", bit_numbering = "msb0", endian = "msb")]
pub struct CFPAPage {
    // Unclear what this header does. Leaving as 0 is fine
    pub header: u32,

    // Monotonically incrementing version counter. This
    // _must_ be incremented on every update!
    #[packed_field(endian = "lsb")]
    pub version: u32,

    // Both fields are related to signed update (sb2)
    // loading. This must be equal or lower than the
    // version specified in the update file
    #[packed_field(endian = "lsb")]
    pub secure_firmware_version: u32,

    #[packed_field(endian = "lsb")]
    pub ns_fw_version: u32,

    // Used to revoke certificates, see 7.3.2.1.2 for
    // details. Keep as 0 for now.
    #[packed_field(endian = "lsb")]
    pub image_key_revoke: u32,

    #[packed_field(endian = "lsb")]
    pub reserved: u32,

    #[packed_field(endian = "lsb")]
    pub rkth_revoke: u32,

    // Used for debug authentication
    #[packed_field(endian = "lsb")]
    pub vendor: u32,

    // Turn peripherals off and on. Leaving as default
    // leaves everything enabled.
    #[packed_field(endian = "lsb")]
    pub dcfg_cc_socu_ns_pin: u32,
    #[packed_field(endian = "lsb")]
    pub dcfg_cc_socu_ns_dflt: u32,

    // Set fault analysis mode
    pub enable_fa_mode: u32,

    // From the sheet
    // "CMPA Page programming on going. This field shall be set to 0x5CC55AA5
    // in the active CFPA page each time CMPA page programming is going on. It
    // shall always be set to 0x00000000 in the CFPA scratch area.
    pub cmpa_prog_in_progress: u32,

    // prince security codes. These are split up to get around rust's
    // limitation of not deriving Default for >256 byte arrays
    pub prince_region0_code0: [u8; 0x20],
    pub prince_region0_code1: [u8; 0x18],
    pub prince_region1_code0: [u8; 0x20],
    pub prince_region1_code1: [u8; 0x18],
    pub prince_region2_code0: [u8; 0x20],
    pub prince_region2_code1: [u8; 0x18],

    // More blank space!
    pub mysterious1: [u8; 0x20],
    pub mysterious2: [u8; 0x8],

    // Rust doesn't like using bit arrays for debugging so
    // split this up
    pub customer_defined0: [u8; 32],
    pub customer_defined1: [u8; 32],
    pub customer_defined2: [u8; 32],
    pub customer_defined3: [u8; 32],
    pub customer_defined4: [u8; 32],
    pub customer_defined5: [u8; 32],
    pub customer_defined6: [u8; 32],

    // This needs to be updated every time
    pub sha256_digest: [u8; 32],
}

impl CFPAPage {
    pub fn set_debug_fields(&mut self, settings: DebugSettings) -> Result<(), PackingError> {
        self.dcfg_cc_socu_ns_pin = settings.pin();
        self.dcfg_cc_socu_ns_dflt = settings.dflt();
        Ok(())
    }

    pub fn update_rkth_revoke(&mut self, rkth: RKTHRevoke) -> Result<(), PackingError> {
        // We're very deliberate about using from_be_bytes here despite
        // the fact that this is technically going to be an le integer.
        // packed_struct does not handle endian byte swapping for structres
        // and the spreadsheet given by NXP gives everything in little
        // endian form. Many other fields in the structure are marked
        // little endian so to avoid a double endian swap here we store
        // the integer as big endian and let the pack() function swap the
        // endian for us.
        self.rkth_revoke = u32::from_be_bytes(rkth.pack()?);

        Ok(())
    }

    pub fn get_rkth_revoke(&self) -> Result<RKTHRevoke, PackingError> {
        RKTHRevoke::unpack(&self.rkth_revoke.to_be_bytes())
    }

    pub fn to_vec(&mut self) -> Result<Vec<u8>, PackingError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.pack()?);
        Ok(bytes)
    }

    pub fn from_bytes(b: &[u8; 512]) -> Result<Self, PackingError> {
        let s = Self::unpack(b)?;
        Ok(s)
    }

    pub fn get_cc_socu_ns_pin(&self) -> Result<CCSOCUPin, PackingError> {
        Ok(CCSOCUPin(self.dcfg_cc_socu_ns_pin))
    }

    pub fn get_cc_socu_ns_dflt(&self) -> Result<CCSOCUDflt, PackingError> {
        Ok(CCSOCUDflt(self.dcfg_cc_socu_ns_dflt))
    }
}

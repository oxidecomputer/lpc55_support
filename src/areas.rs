use anyhow::Result;
use packed_struct::prelude::*;

// Table 183, section 7.3.4
#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum BootImageType {
    PlainImage = 0x0,
    SignedImage = 0x4,
    CRCImage = 0x5,
}

#[derive(PackedStruct)]
#[packed_struct(size_bytes = "4", bit_numbering = "msb0")]
pub struct BootField {
    #[packed_field(ty = "enum", bits = "0..8")]
    pub img_type: EnumCatchAll<BootImageType>,
    #[packed_field(bits = "13")]
    pub tzm_preset: bool,
    #[packed_field(bits = "14")]
    pub tzm_image_type: bool,
}

impl BootField {
    pub fn new(image_type: BootImageType) -> BootField {
        // Table 183, section 7.3.4 for the magic numbers
        BootField {
            // 0 = TZ-M enabled image. Images are only built
            // in secure mode at the moment
            tzm_image_type: false,
            // 0 = no preset data
            tzm_preset: false,
            img_type: image_type.into(),
        }
    }
}

/// All of these have
/// 0 = use DAP to enable, 1 = fixed state
#[repr(C)]
#[derive(Default, Debug, Clone, PackedStruct)]
#[packed_struct(size_bytes = "4", endian = "msb", bit_numbering = "msb0")]
pub struct CCSOCUPin {
    /// Non secure noninvasive debug
    #[packed_field(bits = "0")]
    niden: bool,

    /// Non secure debug enable
    #[packed_field(bits = "1")]
    dbgen: bool,

    /// Secure non invasive debug
    #[packed_field(bits = "2")]
    spniden: bool,

    /// Secure invaisve debug
    #[packed_field(bits = "3")]
    spiden: bool,

    /// JTAG TAP
    #[packed_field(bits = "4")]
    tapen: bool,

    /// micro CM33 debug
    #[packed_field(bits = "5")]
    mcm33_dbg_en: bool,

    /// ISP command
    #[packed_field(bits = "6")]
    isp_cmd_en: bool,

    /// Fault Analysis
    #[packed_field(bits = "7")]
    fa_cmd_en: bool,

    /// Flash Mass Erase
    #[packed_field(bits = "8")]
    me_cmd_en: bool,

    /// micro CM33 non-invasive debug
    #[packed_field(bits = "9")]
    mcm33_nid_en: bool,

    /// Enforce UUID Match during debug auth
    #[packed_field(bits = "15")]
    uuid_check: bool,
}

/// All of these have
/// 0 = disabled, 1 = enabled
#[derive(Default, Debug, Clone, PackedStruct)]
#[packed_struct(size_bytes = "4", bit_numbering = "msb0")]
pub struct CCSOCUDFLT {
    /// Non secure noninvasive debug
    #[packed_field(bits = "0")]
    niden: bool,

    /// Non secure debug enable
    #[packed_field(bits = "1")]
    dbgen: bool,

    /// Secure non invasive debug
    #[packed_field(bits = "2")]
    spniden: bool,

    /// Secure invaisve debug
    #[packed_field(bits = "3")]
    spiden: bool,

    /// JTAG TAP
    #[packed_field(bits = "4")]
    tapen: bool,

    /// micro CM33 debug
    #[packed_field(bits = "5")]
    mcm33_dbg_en: bool,

    /// ISP command
    #[packed_field(bits = "6")]
    isp_cmd_en: bool,

    /// Fault Analysis
    #[packed_field(bits = "7")]
    fa_cmd_en: bool,

    /// Flash Mass Erase
    #[packed_field(bits = "8")]
    me_cmd_en: bool,

    /// micro CM33 non-invasive debug
    #[packed_field(bits = "9")]
    mcm33_nid_en: bool,
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

#[derive(Debug, Clone, PackedStruct)]
#[packed_struct(size_bytes = "4", endian = "lsb", bit_numbering = "lsb0")]
pub struct SecureBootCfg {
    /// Can force boot to 4096 bit keys only
    #[packed_field(ty = "enum", bits = "0..=1")]
    pub rsa4k: EnumCatchAll<RSA4KStatus>,

    /// Include NXP area in DICE calculation
    #[packed_field(ty = "enum", bits = "2..=3")]
    pub dice_inc_nxp_cfg: EnumCatchAll<DiceNXPIncStatus>,

    /// Inlcude Customer area in DICE calculation
    #[packed_field(ty = "enum", bits = "4..=5")]
    pub dice_cust_cfg: EnumCatchAll<DiceCustIncStatus>,

    /// Enable DICE
    #[packed_field(ty = "enum", bits = "6..=7")]
    pub skip_dice: EnumCatchAll<EnableDiceStatus>,

    /// Choose TZ image type. Similar to the field that's in the image at 0x24
    /// See also why the default is to just use what's in the image
    #[packed_field(ty = "enum", bits = "8..=9")]
    pub tzm_image_type: EnumCatchAll<TZMImageStatus>,

    /// Block SetKey PUF operation
    #[packed_field(ty = "enum", bits = "10..=11")]
    pub block_set_key: EnumCatchAll<SetKeyStatus>,

    /// Block EnrollKey Operationg
    #[packed_field(ty = "enum", bits = "12..=13")]
    pub block_enroll: EnumCatchAll<EnrollStatus>,

    /// Undocumented?
    #[packed_field(bits = "14..=15")]
    pub dice_inc_sec_epoch: ReservedZero<packed_bits::Bits<2>>,

    #[packed_field(bits = "29..=16")]
    _reserved: ReservedZero<packed_bits::Bits<14>>,

    /// Enable secure boot
    #[packed_field(ty = "enum", bits = "30..=31")]
    pub sec_boot_en: EnumCatchAll<SecBootStatus>,
}

impl SecureBootCfg {
    pub fn new() -> SecureBootCfg {
        SecureBootCfg {
            rsa4k: RSA4KStatus::RSA2048Keys.into(),
            dice_inc_nxp_cfg: DiceNXPIncStatus::NotIncluded.into(),
            dice_cust_cfg: DiceCustIncStatus::NotIncluded.into(),
            skip_dice: EnableDiceStatus::EnableDice.into(),
            tzm_image_type: TZMImageStatus::InImageHeader.into(),
            block_set_key: SetKeyStatus::EnableKeyCode.into(),
            block_enroll: EnrollStatus::EnableEnroll.into(),
            dice_inc_sec_epoch: ReservedZero::<packed_bits::Bits<2>>::default(),
            _reserved: ReservedZero::<packed_bits::Bits<14>>::default(),
            sec_boot_en: SecBootStatus::PlainImage.into(),
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, PackedStruct)]
#[packed_struct(size_bytes = "512", bit_numbering = "msb0", endian = "lsb")]
pub struct CMPAPage {
    // Features settings such as a boot failure pin, boot speed and
    // default ISP mode. Okay to leave at 0x0
    boot_cfg: u32,

    // Undocumented what this does
    spi_flash_cfg: u32,

    // Can set vendor/product ID
    usb_id: u32,

    // Undocumented what this does
    sdio_cfg: u32,

    // Can turn off various peripherals.
    cc_socu_pin: u32,

    cc_socu_dflt: u32,

    // Related to secure debug
    vendor_usage: u32,

    // Sets boot mode
    secure_boot_cfg: u32,

    // prince settings
    prince_base_addr: u32,
    prince_sr_0: u32,
    prince_sr_1: u32,
    prince_sr_2: u32,

    // These are listed in the manual but not documented at all
    xtal_32khz_capabank_trim: u32,
    xtal_16khz_capabank_trim: u32,

    flash_remap_size: u32,

    blank1: [u8; 0x14],

    // The hash of the RoT keys
    rotkh7: u32,
    rotkh6: u32,
    rotkh5: u32,
    rotkh4: u32,
    rotkh3: u32,
    rotkh2: u32,
    rotkh1: u32,
    rotkh0: u32,

    // For debugging we split up the blank area
    blank2: [u8; 32],
    blank3: [u8; 32],
    blank4: [u8; 32],
    blank5: [u8; 32],
    blank6: [u8; 16],
    customer_defined0: [u8; 32],
    customer_defined1: [u8; 32],
    customer_defined2: [u8; 32],
    customer_defined3: [u8; 32],
    customer_defined4: [u8; 32],
    customer_defined5: [u8; 32],
    customer_defined6: [u8; 32],
    // !!! DO NOT WRITE THIS !!!
    // This will prevent re-writing!
    sha256_digest: [u8; 32],
}

impl CMPAPage {
    pub fn new(sec_boot_cfg: SecureBootCfg) -> Result<CMPAPage> {
        let mut p = CMPAPage::default();

        // We're very deliberate about using from_be_bytes here despite
        // the fact that this is technically going to be an le integer.
        // packed_struct does not handle endian byte swapping for structres
        // and the spreadsheet given by NXP gives everything in little
        // endian form. Many other fields in the structure are marked
        // little endian so to avoid a double endian swap here we store
        // the integer as big endian and let the pack() function swap the
        // endian for us.
        p.secure_boot_cfg = u32::from_be_bytes(sec_boot_cfg.pack()?);

        Ok(p)
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

#[derive(PrimitiveEnum, Copy, Clone, Debug)]
pub enum ROTKeyStatus {
    Invalid = 0x0,
    Enabled = 0x1,
    Revoked1 = 0x2,
    Revoked2 = 0x3,
}

#[derive(Clone, Debug, PackedStruct)]
#[repr(C)]
#[packed_struct(size_bytes = "4", endian = "lsb", bit_numbering = "lsb0")]
pub struct RKTHRevoke {
    #[packed_field(ty = "enum", bits = "1..=0")]
    pub rotk0: EnumCatchAll<ROTKeyStatus>,

    #[packed_field(ty = "enum", bits = "3..=2")]
    pub rotk1: EnumCatchAll<ROTKeyStatus>,

    #[packed_field(ty = "enum", bits = "5..=4")]
    pub rotk2: EnumCatchAll<ROTKeyStatus>,

    #[packed_field(ty = "enum", bits = "7..=6")]
    pub rotk3: EnumCatchAll<ROTKeyStatus>,

    #[packed_field(bits = "31..=8")]
    _reserved: ReservedZero<packed_bits::Bits<24>>,
}

impl RKTHRevoke {
    pub fn new() -> RKTHRevoke {
        RKTHRevoke {
            rotk0: ROTKeyStatus::Invalid.into(),
            rotk1: ROTKeyStatus::Invalid.into(),
            rotk2: ROTKeyStatus::Invalid.into(),
            rotk3: ROTKeyStatus::Invalid.into(),
            _reserved: ReservedZero::<packed_bits::Bits<24>>::default(),
        }
    }
}

#[derive(Clone, Debug, PackedStruct, Default)]
#[repr(C)]
#[packed_struct(size_bytes = "512", bit_numbering = "msb0", endian = "msb")]
pub struct CFPAPage {
    // Unclear what this header does. Leaving as 0 is fine
    header: u32,

    // Monotonically incrementing version counter. This
    // _must_ be incremented on every update!
    #[packed_field(endian = "lsb")]
    version: u32,

    // Both fields are related to signed update (sb2)
    // loading. This must be equal or lower than the
    // version specified in the update file
    #[packed_field(endian = "lsb")]
    pub secure_firmware_version: u32,

    #[packed_field(endian = "lsb")]
    ns_fw_version: u32,

    // Used to revoke certificates, see 7.3.2.1.2 for
    // details. Keep as 0 for now.
    #[packed_field(endian = "lsb")]
    image_key_revoke: u32,

    #[packed_field(endian = "lsb")]
    reserved: u32,

    #[packed_field(endian = "lsb")]
    rkth_revoke: u32,

    // Used for debug authentication
    #[packed_field(endian = "lsb")]
    vendor: u32,

    // Turn peripherals off and on. Leaving as default
    // leaves everything enabled.
    #[packed_field(endian = "lsb")]
    dcfg_cc_socu_ns_pin: u32,
    #[packed_field(endian = "lsb")]
    dcfg_cc_socu_ns_dflt: u32,

    // Set fault analysis mode
    enable_fa_mode: u32,

    // From the sheet
    // "CMPA Page programming on going. This field shall be set to 0x5CC55AA5
    // in the active CFPA page each time CMPA page programming is going on. It
    // shall always be set to 0x00000000 in the CFPA scratch area.
    cmpa_prog_in_progress: u32,

    // prince security codes. These are split up to get around rust's
    // limitation of 256 byte arrays
    prince_region0_code0: [u8; 0x20],
    prince_region0_code1: [u8; 0x18],
    prince_region1_code0: [u8; 0x20],
    prince_region1_code1: [u8; 0x18],
    prince_region2_code0: [u8; 0x20],
    prince_region2_code1: [u8; 0x18],

    // More blank space!
    mysterious1: [u8; 0x20],
    mysterious2: [u8; 0x8],

    // Rust doesn't like using bit arrays for debugging so
    // split this up
    customer_defined0: [u8; 32],
    customer_defined1: [u8; 32],
    customer_defined2: [u8; 32],
    customer_defined3: [u8; 32],
    customer_defined4: [u8; 32],
    customer_defined5: [u8; 32],
    customer_defined6: [u8; 32],

    // This needs to be updated every time
    sha256_digest: [u8; 32],
}

impl CFPAPage {
    pub fn update_version(&mut self) {
        self.version = self.version + 1;
    }

    pub fn update_rkth_revoke(&mut self, rkth: RKTHRevoke) -> Result<()> {
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
}

use igra_core::foundation::util::hex_fmt::hx;
use serde::Serializer;
use std::fmt::LowerHex;

pub fn serialize_with_0x_prefix<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: LowerHex,
{
    serializer.collect_str(&format_args!("{value:#x}"))
}

pub fn serialize_opt_with_0x_prefix<S, T>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: LowerHex,
{
    match value {
        Some(value) => serializer.collect_str(&format_args!("{value:#x}")),
        None => serializer.serialize_none(),
    }
}

pub fn serialize_bytes_with_0x_prefix<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    serializer.collect_str(&format_args!("{:#x}", hx(value.as_ref())))
}

pub fn serialize_opt_bytes_with_0x_prefix<S, T>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    match value {
        Some(value) => serializer.collect_str(&format_args!("{:#x}", hx(value.as_ref()))),
        None => serializer.serialize_none(),
    }
}

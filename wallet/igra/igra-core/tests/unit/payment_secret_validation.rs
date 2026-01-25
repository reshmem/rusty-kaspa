use igra_core::application::pskt_signing::{
    validate_payment_secret_strength, MIN_PAYMENT_SECRET_LENGTH, RECOMMENDED_PAYMENT_SECRET_LENGTH,
};
use kaspa_wallet_core::prelude::Secret;

#[test]
fn test_payment_secret_strength_validation() {
    let empty = Secret::from(String::new());
    let result = validate_payment_secret_strength(&empty);
    assert!(result.is_some());
    assert!(result.unwrap_or_default().contains("empty"));

    let short = Secret::from("short".to_string());
    let result = validate_payment_secret_strength(&short);
    assert!(result.is_some());
    assert!(result.unwrap_or_default().contains("too short"));

    let weak = Secret::from("password123456".to_string());
    let result = validate_payment_secret_strength(&weak);
    assert!(result.is_some());
    assert!(result.unwrap_or_default().contains("weak pattern"));

    let strong = Secret::from("Xy7$mK9#nQ2@pL8!wR5&vZ3%".to_string());
    let result = validate_payment_secret_strength(&strong);
    assert!(result.is_none(), "strong payment_secret should pass validation");
}

#[test]
fn test_payment_secret_constants() {
    assert_eq!(MIN_PAYMENT_SECRET_LENGTH, 12);
    assert_eq!(RECOMMENDED_PAYMENT_SECRET_LENGTH, 16);
}

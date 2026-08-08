//! Public VNC DES auth helper tests.

use brute::protocol::vnc::{vnc_auth_response, vnc_password_key};

/// Known DES vectors from pure-Rust `des` crate (password bit-reversed key).
#[test]
fn vnc_des_response_matches_known_vectors() {
    let challenge = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    assert_eq!(
        vnc_password_key("password"),
        [0x0e, 0x86, 0xce, 0xce, 0xee, 0xf6, 0x4e, 0x26]
    );
    assert_eq!(
        vnc_auth_response("password", &challenge),
        [
            0xb8, 0x66, 0x92, 0x41, 0x25, 0xc8, 0xee, 0xbb, 0x9d, 0xeb, 0xc1, 0xdb, 0x61, 0xc5,
            0x38, 0xe2
        ]
    );

    let challenge2 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    assert_eq!(
        vnc_password_key("pass"),
        [0x0e, 0x86, 0xce, 0xce, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        vnc_auth_response("pass", &challenge2),
        [
            0xfa, 0xb3, 0x40, 0x49, 0xb7, 0x43, 0xef, 0xec, 0xb6, 0x28, 0x7f, 0xfb, 0x55, 0x1d,
            0xce, 0x01
        ]
    );
}

/// Password longer than 8 chars is truncated for the DES key.
#[test]
fn vnc_password_key_truncates_to_eight_bytes() {
    let long = "Q7mP2vN9xR4cT8kL6sD3hW5z";
    let short = "Q7mP2vN9";
    assert_eq!(vnc_password_key(long), vnc_password_key(short));
    assert_eq!(
        vnc_password_key(long),
        [0x8a, 0xec, 0xb6, 0x0a, 0x4c, 0x6e, 0x72, 0x9c]
    );
}

/// Wrong password produces a different DES response for the same challenge.
#[test]
fn vnc_auth_response_differs_for_wrong_password() {
    let challenge = [9u8; 16];
    let good = vnc_auth_response("goodpass", &challenge);
    let bad = vnc_auth_response("badpass!", &challenge);
    assert_ne!(good, bad);
}

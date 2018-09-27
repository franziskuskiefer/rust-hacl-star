extern crate hacl_star;

use hacl_star::randombytes;

#[test]
fn test_randombytes() {
    let mut bytes = [0; 32];
    let mut bytes2 = [0; 32];

    randombytes::randombytes(&mut bytes);
    randombytes::randombytes(&mut bytes2);

    assert_ne!(bytes, bytes2);
}

# ALTCHA Rust Library

A fork of [altcha-lib-rs](https://github.com/jmic/altcha-lib-rs)

[![Crates.io](https://img.shields.io/crates/v/secret-manager.svg)](https://crates.io/crates/altcha-lib)
[![docs.rs](https://docs.rs/secret-manager/badge.svg)](https://docs.rs/altcha-lib)
[![codecov](https://codecov.io/gh/dnp1/altcha-lib-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/dnp1/altcha-lib-rs)

**Community implementation of the ALTCHA library in Rust for your
own server application to create and validate challenges and responses.**

For more information about ALTCHA <https://altcha.org/docs>

---

## Features

- Compatible with the ALTCHA client-side widget
- Generates and validates self-hosted challenges
- Expiring challenges option
- Supports the algorithms SHA256, SHA384, SHA512
- With v0.3, enforces delimited salt to prevent replay attacks; see https://altcha.org/security-advisory/

**Not part of this library:**

- Methods to call ALTCHA's spam filter API
- machine-to-machine ALTCHA
- Store previously verified challenges to prevent replay attacks

## Setup

```toml
[dependencies]
altcha-lib-rs = { version = "0", features = ["json"] }
```

## Example

```rust
use altcha_lib::{create_challenge, verify_json_solution, solve_challenge,
                 Payload, Challenge, ChallengeOptions};
use jiff::{Timestamp, ToSpan};

fn main() {
    // create a challenge
    let challenge = create_challenge(ChallengeOptions {
        hmac_key: "super-secret",
        expires: Some(Timestamp::now().checked_add(5_i64.minutes()).unwrap()),
        ..Default::default()
    }).expect("should be ok");
    // transmit the challenge to the client and let the client solve it
    let res = solve_challenge(&challenge.challenge, &challenge.salt, None, None, 0)
        .expect("need to be solved");
    // pack the solution into a json string
    let payload = Payload {
        algorithm: challenge.algorithm,
        challenge: challenge.challenge,
        number: res,
        salt: challenge.salt,
        signature: challenge.signature,
        took: None,
    };
    let string_payload = serde_json::to_string(&payload).unwrap();

    // receive the solution from the client and verify it
    verify_json_solution(&string_payload, "super-secret", true).expect("should be verified");
}
```
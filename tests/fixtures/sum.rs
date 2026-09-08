//! Reads two integers from stdin and prints their sum.
//!
//! Deliberately dependency-free and `std`-only, so it compiles for
//! `wasm32-wasip1` with a bare `rustc` and no Cargo registry access.

use std::io::Read as _;

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin is provided by the judge");

    let total: i64 = input
        .split_whitespace()
        .map(|token| token.parse::<i64>().expect("the judge supplies integers"))
        .sum();

    println!("{total}");
}

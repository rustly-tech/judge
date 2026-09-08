//! The same program as `sum.rs`, with a deliberate off-by-one.
//!
//! Used to prove the pipeline actually rejects a wrong answer. A judge that only
//! ever returns `AC` passes a happy-path test too.

use std::io::Read as _;

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin is provided by the judge");

    let total: i64 = input
        .split_whitespace()
        .map(|token| token.parse::<i64>().expect("the judge supplies integers"))
        .sum();

    println!("{}", total + 1);
}

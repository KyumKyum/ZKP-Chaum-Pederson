// Code Structure
// Interaction proof between prover(client) and verifier(server).
// Protocol: Chaum-Pedersen Protocol

// Require following functions
// - exponentiate(): a^x mod p
// - solve(): generate s
// - verify(): verify s

// Require following module
// - Random Generator
// - Big Integers
use num_bigint::{BigUint, RandBigInt};
use rand;

//* Exponentiate
// a^x mod b
// output = n^exp mod modulus
pub fn exponentiate(n: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    n.modpow(exp, modulus)
}

//* solve
// output = s = k - c * x mod q
pub fn solve(k: &BigUint, c: &BigUint, x: &BigUint, q: &BigUint) -> BigUint {
    //* If k is less than c*x, it will occur downflow.
    return if *k >= c * x {
        (k - c * x).modpow(&BigUint::from(1u32), q)
    } else {
        q - (c * x - k).modpow(&BigUint::from(1u32), q)
    }
}

//* Verify
// cond1: r1 = a^s * y1^c
// cond2: r2 - b^s * y2^c
pub fn verify(
    r1: &BigUint,
    r2: &BigUint,
    a: &BigUint,
    b: &BigUint,
    y1: &BigUint,
    y2: &BigUint,
    c: &BigUint,
    s: &BigUint,
    p: &BigUint,
) -> bool {
    let cond1: bool = *r1 == (a.modpow(s, p) * y1.modpow(c, p)).modpow(&BigUint::from(1u32), p);
    let cond2: bool = *r2 == (b.modpow(s, p) * y2.modpow(c, p)).modpow(&BigUint::from(1u32), p);

    cond1 && cond2
}

pub fn gen_rand(limit: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng(); //* Generate random number

    rng.gen_biguint_below(limit)
}

#[cfg(test)]
mod test {
    use super::*; //* import all

    #[test]
    fn test_example() {
        //* Public
        let alpha: BigUint = BigUint::from(4u32);
        let beta: BigUint = BigUint::from(9u32);

        let p: BigUint = BigUint::from(23u32); //* Modulus
        let q: BigUint = BigUint::from(11u32);

        //* Secrets
        let x: BigUint = BigUint::from(6u32);
        let k: BigUint = BigUint::from(7u32);

        //* Challenge
        let c: BigUint = BigUint::from(4u32);

        //* Prover
        let y1: BigUint = exponentiate(&alpha, &x, &p); //* This will be computed as 2
        let y2: BigUint = exponentiate(&beta, &x, &p); //* This will be computed as 3

        //* Verifier
        let r1: BigUint = exponentiate(&alpha, &k, &p); //* This will be computed as 8
        let r2: BigUint = exponentiate(&beta, &k, &p); //* This will be computed as 4

        //* Assertions
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        //* Solve
        let s: BigUint = solve(&k, &c, &x, &q); //* This will be computed as 5

        //* Assertion
        assert_eq!(s, BigUint::from(5u32));

        //* Verify
        let res: bool = verify(&r1, &r2, &alpha, &beta, &y1, &y2, &c, &s, &p); //* This will be computed as true.

        //* Assertion
        assert!(res); //* Assert to be true

        //* Eavesdropped key
        let evas_x: BigUint = BigUint::from(7u32);
        let evas_s: BigUint = solve(&k, &c, &evas_x, &q);
        let evas_res: bool = verify(&r1, &r2, &alpha, &beta, &y1, &y2, &c, &evas_s, &p); //* This will be computed as false.

        //* Assertion
        assert!(!evas_res);
    }

    #[test]
    fn test_rand(){
        let rand1: BigUint = gen_rand(&BigUint::from(100u32));
        let rand2: BigUint = gen_rand(&BigUint::from(100u32));

        println!("{}", rand1);
        println!("{}", rand2);
    }
}

// Code Structure
// Interaction proof between prover(client) and verifier(server).
// Protocol: Chaum-Pedersen Protocol

// Require following functions
// - exponentiate(): a^x mod P
// - solve(): generate s
// - verify(): verify s


// Require following module
// - Random Generator
// - Big Integers


mod constant;

//* module zkp chaum-pedersen
pub mod zkp_cp {
    use num_bigint::{BigUint, RandBigInt};
    use rand;
    use rand::Rng;
    use crate::constant;

    pub struct  ZKP {
        pub p: BigUint,
        pub q: BigUint,
        pub alpha: BigUint,
        pub beta: BigUint,
    }

    impl ZKP {
        //* pow
        // a^x mod b
        // output = n^exp mod modulus
        pub fn pow(n: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
            n.modpow(exp, modulus)
        }

        //* solve
        // output = s = k - c * x mod q
        pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
            //* If k is less than c*x, it will occur downflow.
            return if *k >= c * x {
                (k - c * x).modpow(&BigUint::from(1u32), &self.q)
            } else {
                &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q)
            }
        }

        //* Verify
// cond1: r1 = a^s * y1^c
// cond2: r2 - b^s * y2^c
        pub fn verify(
            &self,
            r1: &BigUint,
            r2: &BigUint,
            y1: &BigUint,
            y2: &BigUint,
            c: &BigUint,
            s: &BigUint,
        ) -> bool {
            let cond1: bool = *r1 == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

            let cond2: bool = *r2 == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

            cond1 && cond2
        }

        pub fn gen_rand(limit: &BigUint) -> BigUint {
            let mut rng = rand::thread_rng(); //* Generate random number

            rng.gen_biguint_below(limit)
        }

        pub fn gen_rand_str(size: usize) -> String {
            rand::thread_rng()
                .sample_iter(rand::distributions::Alphanumeric)
                .take(size)
                .map(char::from)
                .collect() //* Collect all char generated.
        }

        pub fn get_const() -> (BigUint, BigUint, BigUint, BigUint) {
            let (P,G,Q) = constant::gen_large_prime();
            let p: BigUint = BigUint::from_bytes_be(&P);
            let q: BigUint = BigUint::from_bytes_be(&Q);

            //* Public
            let alpha: BigUint = BigUint::from_bytes_be(&G);
            //* alpha^x is also will be a generator -> define as an beta
            let beta: BigUint = alpha.modpow(&ZKP::gen_rand(&q), &p);

            (alpha, beta, p, q)
        }
    }
}


//* TEST
//==========================

#[cfg(test)]
mod test {
    use super::*; //* import all
    use num_bigint::{BigUint, RandBigInt};
    use rand;
    use zkp_cp::ZKP;
    use constant;
    #[test]
    fn test_1024bits() {
        //* Init
        let (P,G,Q) = constant::gen_large_prime();

        let p: BigUint = BigUint::from_bytes_be(&P);
        let q: BigUint = BigUint::from_bytes_be(&Q);

        //* Public
        let alpha: BigUint = BigUint::from_bytes_be(&G);
        //* alpha^x is also will be a generator -> define as an beta
        let beta: BigUint = alpha.modpow(&ZKP::gen_rand(&q), &p);

        //* ZKP Protocol Structure
        let zkp:ZKP = ZKP{
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone()
        };

        //* Secrets
        let x: BigUint = ZKP::gen_rand(&q);
        let k: BigUint = ZKP::gen_rand(&q);

        //* Challenge
        let c: BigUint = ZKP::gen_rand(&q);

        //* Prover
        let y1: BigUint = ZKP::pow(&alpha, &x, &p); //* This will be computed as 2
        let y2: BigUint = ZKP::pow(&beta, &x, &p); //* This will be computed as 3

        //* Verifier
        let r1: BigUint = ZKP::pow(&alpha, &k, &p); //* This will be computed as 8
        let r2: BigUint = ZKP::pow(&beta, &k, &p); //* This will be computed as 4

        //* Solve
        let s: BigUint = zkp.solve(&k, &c, &x); //* This will be computed as 5

        //* Assertion
        //* Verify
        let res: bool = zkp.verify(&r1, &r2, &y1, &y2, &c, &s); //* This will be computed as true.

        //* Assertion
        assert!(res); //* Assert to be true

        //* Eavesdropped key
        let eaves_x: BigUint = BigUint::from(7u32);
        let eaves_s: BigUint = zkp.solve(&k, &c, &eaves_x);
        let eaves_res: bool = zkp.verify(&r1, &r2, &y1, &y2, &c, &eaves_s); //* This will be computed as false.

        //* Assertion
        assert!(!eaves_res);
    }

    #[test]
    fn test_rand(){
        let rand1: BigUint = ZKP::gen_rand(&BigUint::from(100u32));
        let rand2: BigUint = ZKP::gen_rand(&BigUint::from(100u32));

        println!("{}", rand1);
        println!("{}", rand2);
    }

    #[test]
    fn test_example(){
        //* Public
        let alpha: BigUint = BigUint::from(4u32);
        let beta: BigUint = BigUint::from(9u32);

        let p: BigUint = BigUint::from(23u32); //* Modulus
        let q: BigUint = BigUint::from(11u32);

        //* ZKP Protocol Structure
        let zkp:ZKP = ZKP{
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone()
        };

        //* Secrets
        let x: BigUint = BigUint::from(6u32);
        let k: BigUint = BigUint::from(7u32);

        //* Challenge
        let c: BigUint = BigUint::from(4u32);

        //* Prover
        let y1: BigUint = ZKP::pow(&alpha, &x, &p); //* This will be computed as 2
        let y2: BigUint = ZKP::pow(&beta, &x, &p); //* This will be computed as 3

        //* Verifier
        let r1: BigUint = ZKP::pow(&alpha, &k, &p); //* This will be computed as 8
        let r2: BigUint = ZKP::pow(&beta, &k, &p); //* This will be computed as 4

        //* Assertions
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        //* Solve
        let s: BigUint = zkp.solve(&k, &c, &x); //* This will be computed as 5

        //* Assertion
        assert_eq!(s, BigUint::from(5u32));

        //* Verify
        let res: bool = zkp.verify(&r1, &r2, &y1, &y2, &c, &s); //* This will be computed as true.

        //* Assertion
        assert!(res); //* Assert to be true

        //* Eavesdropped key
        let eaves_x: BigUint = BigUint::from(7u32);
        let eaves_s: BigUint = zkp.solve(&k, &c, &eaves_x);
        let eaves_res: bool = zkp.verify(&r1, &r2, &y1, &y2, &c, &eaves_s); //* This will be computed as false.

        //* Assertion
        assert!(!eaves_res);
    }
}

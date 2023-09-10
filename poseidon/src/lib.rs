pub mod constants;
pub mod poseidon;
use ff::*;
use once_cell::sync::OnceCell;
pub use poseidon::*;

pub fn poseidon_fields(input_fields: &[Fr]) -> Result<Fr, PoseidonError> {
    let poseidon = poseidon_default();
    poseidon.hash(input_fields.to_vec())
}

pub fn poseidon_bytes(input_bytes: &[u8]) -> Result<Fr, PoseidonError> {
    let input_fields = input_bytes
        .into_iter()
        .map(|b| Fr::from_u128(*b as u128))
        .collect::<Vec<_>>();
    compose_and_poseidon(&input_fields, 31)
}

pub fn compose_and_poseidon(
    input_fields: &[Fr],
    num_composed_fields: usize,
) -> Result<Fr, PoseidonError> {
    let mut composed_fields = Vec::new();
    for fields in input_fields.chunks(num_composed_fields) {
        let mut sum = Fr::ZERO;
        let mut coeff = Fr::ONE;
        for field in fields.into_iter() {
            sum += *field * coeff;
            coeff *= Fr::from_u128(2);
        }
        composed_fields.push(sum);
    }
    poseidon_fields(&composed_fields)
}

fn poseidon_default() -> &'static Poseidon {
    static POSEIDON: OnceCell<Poseidon> = OnceCell::new();

    POSEIDON
        .get_or_try_init(|| Ok::<Poseidon, ()>(Poseidon::new()))
        .expect("Fail to init Poseidon")
}

// use serde::{Deserialize, Serialize};

// BN254 Scalar Field F_r
#[derive(PrimeField)]
#[PrimeFieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Fr([u64; 4]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ff() {
        let a = Fr::from_u128(2);
        assert_eq!(a, Fr::from_str_vartime("2").unwrap(),);

        let b: Fr = Fr::from_str_vartime(
            "21888242871839275222246405745257275088548364400416034343698204186575808495619",
        )
        .unwrap();
        assert_eq!(b, Fr::from_str_vartime("2").unwrap(),);
        assert_eq!(&a, &b);
    }

    // #[test]
    // fn test_load_constants() {
    //     let cons = load_constants();
    //     assert_eq!(
    //         cons.c[0][0].to_string(),
    //         "Fr(0x09c46e9ec68e9bd4fe1faaba294cba38a71aa177534cdd1b6c7dc0dbd0abd7a7)"
    //     );
    //     assert_eq!(
    //         cons.c[cons.c.len() - 1][0].to_string(),
    //         "Fr(0x2088ce9534577bf38be7bc457f2756d558d66e0c07b9cc001a580bd42cda0e77)"
    //     );
    //     assert_eq!(
    //         cons.m[0][0][0].to_string(),
    //         "Fr(0x066f6f85d6f68a85ec10345351a23a3aaf07f38af8c952a7bceca70bd2af7ad5)"
    //     );
    //     assert_eq!(
    //         cons.m[cons.m.len() - 1][0][0].to_string(),
    //         "Fr(0x0190f922d97c8a7dcf0a142a3be27749d1c64bc22f1c556aaa24925d158cac56)"
    //     );
    // }

    #[test]
    fn test_hash() {
        let b0: Fr = Fr::from_str_vartime("0").unwrap();
        let b1: Fr = Fr::from_str_vartime("1").unwrap();
        let b2: Fr = Fr::from_str_vartime("2").unwrap();
        let b3: Fr = Fr::from_str_vartime("3").unwrap();
        let b4: Fr = Fr::from_str_vartime("4").unwrap();
        let b5: Fr = Fr::from_str_vartime("5").unwrap();
        let b6: Fr = Fr::from_str_vartime("6").unwrap();
        let b7: Fr = Fr::from_str_vartime("7").unwrap();
        let b8: Fr = Fr::from_str_vartime("8").unwrap();
        let b9: Fr = Fr::from_str_vartime("9").unwrap();
        let b10: Fr = Fr::from_str_vartime("10").unwrap();
        let b11: Fr = Fr::from_str_vartime("11").unwrap();
        let b12: Fr = Fr::from_str_vartime("12").unwrap();
        let b13: Fr = Fr::from_str_vartime("13").unwrap();
        let b14: Fr = Fr::from_str_vartime("14").unwrap();
        let b15: Fr = Fr::from_str_vartime("15").unwrap();
        let b16: Fr = Fr::from_str_vartime("16").unwrap();

        // let poseidon = Poseidon::new();

        let big_arr: Vec<Fr> = vec![b1];
        // let mut big_arr: Vec<Fr> = Vec::new();
        // big_arr.push(b1.clone());
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133)" // "18586133768512220936620570745912940619677854269274689475585506675881198879027"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "18586133768512220936620570745912940619677854269274689475585506675881198879027"
            )
            .unwrap()
        );

        let big_arr: Vec<Fr> = vec![b1, b2];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a)" // "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "7853200120776062878684798364095072458815029376092732009249414926327459813530"
            )
            .unwrap()
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b0, b0, b0];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x024058dd1e168f34bac462b6fffe58fd69982807e9884c1c6148182319cee427)" // "1018317224307729531995786483840663576608797660851238720571059489595066344487"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "1018317224307729531995786483840663576608797660851238720571059489595066344487"
            )
            .unwrap()
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b0, b0, b0, b0];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x21e82f465e00a15965e97a44fe3c30f3bf5279d8bf37d4e65765b6c2550f42a1)" // "15336558801450556532856248569924170992202208561737609669134139141992924267169"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "15336558801450556532856248569924170992202208561737609669134139141992924267169"
            )
            .unwrap()
        );

        let big_arr: Vec<Fr> = vec![b3, b4, b0, b0, b0];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x0cd93f1bab9e8c9166ef00f2a1b0e1d66d6a4145e596abe0526247747cc71214)" // "5811595552068139067952687508729883632420015185677766880877743348592482390548"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "5811595552068139067952687508729883632420015185677766880877743348592482390548"
            )
            .unwrap(),
        );

        let big_arr: Vec<Fr> = vec![b3, b4, b0, b0, b0, b0];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x1b1caddfc5ea47e09bb445a7447eb9694b8d1b75a97fff58e884398c6b22825a)" // "12263118664590987767234828103155242843640892839966517009184493198782366909018"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "12263118664590987767234828103155242843640892839966517009184493198782366909018"
            )
            .unwrap()
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b3, b4, b5, b6];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x2d1a03850084442813c8ebf094dea47538490a68b05f2239134a4cca2f6302e1)" // "20400040500897583745843009878988256314335038853985262692600694741116813247201"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "20400040500897583745843009878988256314335038853985262692600694741116813247201"
            )
            .unwrap()
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x1278779aaafc5ca58bf573151005830cdb4683fb26591c85a7464d4f0e527776)", // "8354478399926161176778659061636406690034081872658507739535256090879947077494"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "8354478399926161176778659061636406690034081872658507739535256090879947077494"
            )
            .unwrap()
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x0c3fbfb4d3f583df4124b4b3ac94ca3a0a1948a89fef727204d89de1c4d35693)", // "5540388656744764564518487011617040650780060800286365721923524861648744699539"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "5540388656744764564518487011617040650780060800286365721923524861648744699539"
            )
            .unwrap()
        );

        let big_arr: Vec<Fr> = vec![
            b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0, b0, b0,
        ];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x1a456f8563b98c9649877f38b7e36534b241c29d457d307c481cbd12b69bb721)", // "11882816200654282475720830292386643970958445617880627439994635298904836126497"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "11882816200654282475720830292386643970958445617880627439994635298904836126497"
            )
            .unwrap()
        );

        let big_arr: Vec<Fr> = vec![
            b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16,
        ];
        let h = poseidon_fields(&big_arr).unwrap();
        // assert_eq!(
        //     h.to_string(),
        //     "Fr(0x16159a551cbb66108281a48099fff949ae08afd7f1f2ec06de2ffb96b919b765)", // "9989051620750914585850546081941653841776809718687451684622678807385399211877"
        // );
        assert_eq!(
            h,
            Fr::from_str_vartime(
                "9989051620750914585850546081941653841776809718687451684622678807385399211877"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_wrong_inputs() {
        let b0: Fr = Fr::from_str_vartime("0").unwrap();
        let b1: Fr = Fr::from_str_vartime("1").unwrap();
        let b2: Fr = Fr::from_str_vartime("2").unwrap();

        // let poseidon = Poseidon::new();

        let big_arr: Vec<Fr> = vec![
            b1, b2, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0,
        ];
        poseidon_fields(&big_arr).expect_err("Wrong inputs length");
    }
}

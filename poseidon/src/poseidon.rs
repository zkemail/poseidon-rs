use crate::constants::*;
use crate::Fr;
use halo2curves::ff::*;
use std::ops::{AddAssign, MulAssign};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PoseidonError {
    #[error("Wrong inputs length: max length is `{0}` but got `{1}`")]
    WrongInputsLength(usize, usize),
}

#[derive(Debug, Clone)]
pub struct Poseidon {
    constants: Constants,
}
impl Poseidon {
    pub fn new() -> Poseidon {
        Poseidon {
            constants: load_constants(),
        }
    }
    pub fn ark(&self, state: &mut Vec<Fr>, c: &Vec<Fr>, it: usize) {
        for i in 0..state.len() {
            state[i].add_assign(&c[it + i]);
        }
    }

    pub fn sbox(&self, n_rounds_f: usize, n_rounds_p: usize, state: &mut Vec<Fr>, i: usize) {
        if i < n_rounds_f / 2 || i >= n_rounds_f / 2 + n_rounds_p {
            for j in 0..state.len() {
                let aux = state[j];
                state[j] = state[j].square();
                state[j] = state[j].square();
                state[j].mul_assign(&aux);
            }
        } else {
            let aux = state[0];
            state[0] = state[0].square();
            state[0] = state[0].square();
            state[0].mul_assign(&aux);
        }
    }

    pub fn mix(&self, state: &Vec<Fr>, m: &Vec<Vec<Fr>>) -> Vec<Fr> {
        let mut new_state: Vec<Fr> = Vec::new();
        for i in 0..state.len() {
            new_state.push(Fr::ZERO);
            for j in 0..state.len() {
                let mut mij = m[i][j];
                mij.mul_assign(&state[j]);
                new_state[i].add_assign(&mij);
            }
        }
        new_state.clone()
    }

    pub fn hash(&self, inp: Vec<Fr>) -> Result<Fr, PoseidonError> {
        let t = inp.len() + 1;
        // if inp.len() == 0 || inp.len() >= self.constants.n_rounds_p.len() - 1 {
        if inp.is_empty() || inp.len() > self.constants.n_rounds_p.len() {
            return Err(PoseidonError::WrongInputsLength(
                self.constants.n_rounds_p.len(),
                inp.len(),
            ));
        }
        let n_rounds_f = self.constants.n_rounds_f.clone();
        let n_rounds_p = self.constants.n_rounds_p[t - 2].clone();

        let mut state = vec![Fr::ZERO; t];
        state[1..].clone_from_slice(&inp);

        for i in 0..(n_rounds_f + n_rounds_p) {
            self.ark(&mut state, &self.constants.c[t - 2], i * t);
            self.sbox(n_rounds_f, n_rounds_p, &mut state, i);
            state = self.mix(&state, &self.constants.m[t - 2]);
        }

        Ok(state[0])
    }
}

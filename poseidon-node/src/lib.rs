use halo2curves::serde::SerdeObject;
use hex;
use neon::prelude::*;
use poseidon_rs::{compose_and_poseidon, poseidon_bytes, poseidon_fields, Fr};
use std::convert::TryInto;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("poseidonFields", poseidon_fields_node)?;
    cx.export_function("poseidonBytes", poseidon_bytes_node)?;
    cx.export_function("composeAndPoseidon", compose_and_poseidon_node)?;
    Ok(())
}

/// function poseidonFields(input_strs: string[]): string.
/// input_strs: an array of hex string with 0x prefix.
/// return: a hex string with 0x prefix.
fn poseidon_fields_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let input_strs = cx.argument::<JsArray>(0)?;
    let inputs = strs_to_fields(&mut cx, &input_strs)?;
    match poseidon_fields(&inputs) {
        Ok(result) => {
            let result_str = field2str(&result);
            Ok(cx.string(result_str))
        }
        Err(e) => return cx.throw_error(&format!("poseidon_fields failed: {}", e)),
    }
}

/// function poseidonBytes(input_str: string): string.
/// input_str: a hex string with 0x prefix.
/// return: a hex string with 0x prefix.
fn poseidon_bytes_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let input_strs = cx.argument::<JsString>(0)?.value(&mut cx);
    if &input_strs[0..2] != "0x" {
        return cx.throw_error("the input string must be hex string with 0x prefix");
    }
    let bytes = match hex::decode(&input_strs[2..]) {
        Ok(bytes) => bytes,
        Err(e) => return cx.throw_error(&format!("the input string is invalid hex: {}", e)),
    };
    match poseidon_bytes(&bytes) {
        Ok(result) => {
            let result_str = field2str(&result);
            Ok(cx.string(result_str))
        }
        Err(e) => return cx.throw_error(&format!("poseidon_bytes failed: {}", e)),
    }
}

/// function composeAndPoseidon(input_strs: string[], num_composed_chunks: number, bits_of_chunk] number): string.
/// input_strs: an array of hex string with 0x prefix.
/// num_composed_chunks: number of chunks to compose.
/// bits_of_chunk: number of bits of each chunk.
/// return: a hex string with 0x prefix.
fn compose_and_poseidon_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let input_strs = cx.argument::<JsArray>(0)?;
    let num_composed_chunks = cx.argument::<JsNumber>(1)?.value(&mut cx) as usize;
    let bits_of_chunk = cx.argument::<JsNumber>(1)?.value(&mut cx) as u128;
    let inputs = strs_to_fields(&mut cx, &input_strs)?;
    match compose_and_poseidon(&inputs, num_composed_chunks, bits_of_chunk) {
        Ok(result) => {
            let result_str = field2str(&result);
            Ok(cx.string(result_str))
        }
        Err(e) => return cx.throw_error(&format!("compose_and_poseidon failed: {}", e)),
    }
}

fn strs_to_fields(cx: &mut FunctionContext, array: &JsArray) -> NeonResult<Vec<Fr>> {
    let len = array.len(cx);
    let mut fields = vec![];
    for idx in 0..len {
        // 0x + 64 hex chars (32 bytes)
        let hex_str = array.get::<JsString, _, _>(cx, idx)?.value(cx);
        let field = str2field(cx, &hex_str)?;
        fields.push(field);
    }
    Ok(fields)
}

fn str2field(cx: &mut FunctionContext, input_strs: &str) -> NeonResult<Fr> {
    if &input_strs[0..2] != "0x" {
        return cx.throw_error(&format!(
            "the input string {} must be hex string with 0x prefix",
            &input_strs
        ));
    }
    let mut bytes = match hex::decode(&input_strs[2..]) {
        Ok(bytes) => bytes,
        Err(e) => {
            return cx.throw_error(&format!(
                "the input string {} is invalid hex: {}",
                &input_strs, e
            ))
        }
    };
    bytes.reverse();
    if bytes.len() != 32 {
        return cx.throw_error(&format!(
            "the input string {} must be 32 bytes but is {} bytes",
            &input_strs,
            bytes.len()
        ));
    }
    Ok(Fr::from_bytes(&bytes.try_into().unwrap()).unwrap())
}

fn field2str(field: &Fr) -> String {
    format!("{:?}", field)
}

use rspow::bench::{
    argon2_params_kib, bench_argon2_leading_bits_once, csv_header, csv_row_run, csv_row_summary,
    summarize, BenchOutcome, BenchSummary,
};
use serde::Serialize;
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

const ALGO: &str = "argon2id";
const MODE: &str = "leading_zero_bits";

#[derive(Serialize)]
struct BenchRunPayload {
    outcome: BenchOutcome,
    csv: String,
}

#[derive(Serialize)]
struct SummaryPayload {
    summary: BenchSummary,
    csv: String,
}

#[wasm_bindgen]
pub fn bench_csv_header() -> String {
    csv_header().to_owned()
}

#[wasm_bindgen]
pub fn bench_once(
    bits: u32,
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
    data: &str,
    start_nonce: u64,
    run_idx: u32,
) -> Result<JsValue, JsValue> {
    let params = argon2_params_kib(m_kib, t_cost, p_cost).map_err(to_js_err)?;
    let outcome =
        bench_argon2_leading_bits_once(data.as_bytes(), bits, &params, start_nonce)
            .map_err(to_js_err)?;
    let csv = csv_row_run(&outcome, ALGO, MODE, run_idx);
    to_value(&BenchRunPayload { outcome, csv }).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn summarize_runs(
    bits: u32,
    data_len: usize,
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
    outcomes: JsValue,
) -> Result<JsValue, JsValue> {
    let outcomes: Vec<BenchOutcome> = from_value(outcomes)
        .map_err(|err| JsValue::from_str(&format!("failed to decode outcomes: {err}")))?;
    let summary = summarize(&outcomes).map_err(to_js_err)?;
    let csv = csv_row_summary(bits, data_len, m_kib, t_cost, p_cost, &summary, ALGO, MODE);
    to_value(&SummaryPayload { summary, csv }).map_err(|err| JsValue::from_str(&err.to_string()))
}

fn to_js_err(err: String) -> JsValue {
    JsValue::from_str(&err)
}

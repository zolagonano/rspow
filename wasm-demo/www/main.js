import init, { bench_csv_header, bench_once, summarize_runs } from "./pkg/wasm_demo.js";

let wasmReady = false;
async function ensureWasm() {
  if (!wasmReady) {
    await init();
    wasmReady = true;
  }
}

const form = document.getElementById("config-form");
const output = document.getElementById("csv-output");
const statusEl = document.getElementById("status");
const stopBtn = document.getElementById("stop-btn");

let abortFlag = false;
stopBtn.addEventListener("click", () => {
  abortFlag = true;
  statusEl.textContent = "Stop requested";
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  abortFlag = false;

  try {
    await ensureWasm();
    const startBits = parsePositiveInt(document.getElementById("start-bits").value, "start-bits");
    const maxBits = parsePositiveInt(document.getElementById("max-bits").value, "max-bits");
    if (maxBits < startBits) {
      throw new Error("max-bits must be >= start-bits");
    }
    const repeats = parsePositiveInt(document.getElementById("repeats").value, "repeats");
    const data = document.getElementById("data").value;
    const dataLen = new TextEncoder().encode(data).length;
    const memoryMib = parsePositiveInt(document.getElementById("memory-mib").value, "memory-mib");
    const mKib = memoryMib * 1024;
    const tCost = parsePositiveInt(document.getElementById("t-cost").value, "t-cost");
    const pCost = parsePositiveInt(document.getElementById("p-cost").value, "p-cost");
    const randomStart = document.getElementById("random-start").checked;
    const seedInput = document.getElementById("seed").value.trim();

    let seededRng = null;
    if (seedInput.length > 0) {
      const seedValue = parseSeed(seedInput);
      seededRng = createSplitMix64(seedValue);
    }

    const lines = [bench_csv_header()];
    output.value = lines.join("\n");

    for (let bits = startBits; bits <= maxBits; bits += 1) {
      const outcomes = [];
      for (let runIdx = 0; runIdx < repeats; runIdx += 1) {
        if (abortFlag) {
          statusEl.textContent = "已停止";
          return;
        }
        const startNonce = selectStartNonce(randomStart, seededRng, runIdx);
        const result = bench_once(bits, mKib, tCost, pCost, data, startNonce, runIdx);
        if (!result || !result.outcome) {
          throw new Error("Empty result returned by bench_once");
        }
        lines.push(result.csv);
        outcomes.push(result.outcome);
        output.value = lines.join("\n");
        statusEl.textContent = `bits=${bits} run=${runIdx + 1}/${repeats}`;
        await nextTick();
      }

      const summaryPayload = summarize_runs(bits, dataLen, mKib, tCost, pCost, outcomes);
      lines.push(summaryPayload.csv);
      output.value = lines.join("\n");
      statusEl.textContent = `bits=${bits} completed`;
      await nextTick();
    }

    statusEl.textContent = "All done";
  } catch (err) {
    console.error(err);
    statusEl.textContent = `Error: ${err}`;
  }
});

function parsePositiveInt(value, name) {
  const num = Number.parseInt(value, 10);
  if (!Number.isFinite(num) || num <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return num;
}

function parseSeed(value) {
  try {
    return BigInt(value);
  } catch (err) {
    throw new Error("seed must be an integer in 0..2^64-1");
  }
}

function createSplitMix64(seed) {
  let state = BigInt.asUintN(64, seed);
  return () => {
    state = BigInt.asUintN(64, state + 0x9e3779b97f4a7c15n);
    let z = state;
    z = BigInt.asUintN(64, (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n);
    z = BigInt.asUintN(64, (z ^ (z >> 27n)) * 0x94d049bb133111ebn);
    z = BigInt.asUintN(64, z ^ (z >> 31n));
    return z;
  };
}

function selectStartNonce(randomStart, seededRng, runIdx) {
  if (!randomStart) {
    return BigInt(runIdx);
  }
  if (seededRng) {
    return seededRng();
  }
  const buffer = new BigUint64Array(1);
  crypto.getRandomValues(buffer);
  return buffer[0];
}

function nextTick() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

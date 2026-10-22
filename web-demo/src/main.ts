import init, { verify_pczt, version } from "./wasm/pczt_guard_wasm.js";
import wasmUrl from "./wasm/pczt_guard_wasm_bg.wasm?url";

type Verdict = "SAFE" | "UNSAFE" | "CANNOT_VERIFY";
type Severity = "INFO" | "WARN" | "CANNOT_VERIFY" | "UNSAFE";

interface Payment {
  pool: string;
  value: number | null;
  shown: string | null;
  committed: string | null;
  bound: boolean;
}

interface Finding {
  code: string;
  severity: Severity;
  lint?: string;
  pool: string | null;
  index: number | null;
  detail: string;
}

interface Report {
  verdict: Verdict;
  network: string | { other: number };
  tx_version: number;
  branch_id: number;
  pools: string[];
  payments: Payment[];
  fee: number | null;
  findings: Finding[];
}

const drop = element<HTMLDivElement>("drop");
const fileInput = element<HTMLInputElement>("file");
const networkSelect = element<HTMLSelectElement>("network");
const strictBox = element<HTMLInputElement>("strict");
const unlabeledBox = element<HTMLInputElement>("unlabeled");
const reportEl = element<HTMLElement>("report");
const versionEl = element<HTMLElement>("version");

let loaded: { name: string; bytes: Uint8Array } | null = null;

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`missing element #${id}`);
  return found as T;
}

async function main(): Promise<void> {
  await init({ module_or_path: wasmUrl });
  versionEl.textContent = `pczt-guard ${version()} · WebAssembly`;

  drop.addEventListener("click", () => fileInput.click());
  drop.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      fileInput.click();
    }
  });
  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (file) void loadFile(file.name, new Uint8Array(0), file);
  });

  for (const type of ["dragenter", "dragover"]) {
    drop.addEventListener(type, (event) => {
      event.preventDefault();
      drop.classList.add("over");
    });
  }
  for (const type of ["dragleave", "drop"]) {
    drop.addEventListener(type, () => drop.classList.remove("over"));
  }
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    const file = event.dataTransfer?.files?.[0];
    if (file) void loadFile(file.name, new Uint8Array(0), file);
  });

  for (const box of [networkSelect, strictBox, unlabeledBox]) {
    box.addEventListener("change", () => {
      if (loaded) verify(loaded.name, loaded.bytes);
    });
  }

  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-sample]")) {
    button.addEventListener("click", () => void loadSample(button.dataset.sample ?? ""));
  }

  // Deep link, handy for demos and for testing the built page: ?sample=<name>
  const sample = new URLSearchParams(window.location.search).get("sample");
  if (sample) await loadSample(sample);
}

async function loadFile(name: string, _placeholder: Uint8Array, file: File): Promise<void> {
  loaded = { name, bytes: new Uint8Array(await file.arrayBuffer()) };
  verify(loaded.name, loaded.bytes);
}

async function loadSample(name: string): Promise<void> {
  try {
    const response = await fetch(`fixtures/${name}.pczt`);
    // A dev server — and any static host with an SPA fallback — answers 200 with index.html
    // for a path that does not exist, so the status alone cannot tell a real fixture from a
    // missing one. Without this the page reports "not a PCZT", which blames the file for a
    // typo in the URL.
    const contentType = response.headers.get("content-type") ?? "";
    if (!response.ok || contentType.includes("text/html")) {
      throw new Error(`there is no sample called "${name}"`);
    }
    loaded = { name: `${name}.pczt`, bytes: new Uint8Array(await response.arrayBuffer()) };
    verify(loaded.name, loaded.bytes);
  } catch (error) {
    showError(
      `cannot load the sample: ${describe(error)}. Known samples: ironwood-honest, ` +
        `ironwood-address-tampered, ironwood-fee-drain. If they are missing entirely, run ` +
        `\`npm run fixtures\`.`,
    );
  }
}

function verify(name: string, bytes: Uint8Array): void {
  try {
    const json = verify_pczt(
      bytes,
      networkSelect.value === "" ? null : networkSelect.value,
      strictBox.checked,
      unlabeledBox.checked,
    );
    render(name, JSON.parse(json) as Report);
  } catch (error) {
    showError(describe(error));
  }
}

function render(name: string, report: Report): void {
  const verdictClass =
    report.verdict === "SAFE" ? "safe" : report.verdict === "UNSAFE" ? "unsafe" : "cannot";
  const verdictLabel = report.verdict.replace("_", " ");

  const parts: string[] = [
    `<div class="verdict ${verdictClass}">${escape(verdictLabel)}
       <small>${escape(name)}</small>
     </div>`,
    `<div class="meta">${escape(networkName(report.network))} · tx v${report.tx_version} · ${
      report.pools.length > 0 ? report.pools.map(escape).join(" + ") : "no inputs or outputs"
    }</div>`,
  ];

  if (report.payments.length > 0) {
    parts.push('<ul class="payments">');
    for (const payment of report.payments) {
      const badge = payment.bound
        ? '<span class="badge ok">verified</span>'
        : payment.shown === null
          ? '<span class="badge unknown">no label</span>'
          : '<span class="badge bad">not verified</span>';
      const amount = payment.value === null ? "unknown" : zec(payment.value);
      const shown = payment.shown ? shorten(payment.shown) : "(no address)";
      const committed =
        payment.committed && payment.committed !== payment.shown
          ? `<br />actually pays <strong>${escape(shorten(payment.committed))}</strong>`
          : "";
      parts.push(
        `<li class="payment">
           <span class="pool">${escape(payment.pool)}</span>
           <span class="amount">${escape(amount)}</span>
           ${badge}
           <span class="address">${escape(shown)}${committed}</span>
         </li>`,
      );
    }
    if (report.fee !== null) {
      parts.push(
        `<li class="payment">
           <span class="pool">fee</span>
           <span class="amount">${escape(zec(report.fee))}</span>
           <span></span><span class="address"></span>
         </li>`,
      );
    }
    parts.push("</ul>");
  }

  if (report.findings.length > 0) {
    parts.push('<ul class="findings">');
    for (const finding of report.findings) {
      const severity = finding.severity.toLowerCase().replace("_", "");
      const lint = finding.lint ? `<span class="lint">${escape(finding.lint)}</span>` : "";
      parts.push(
        `<li class="finding">
           <span class="severity ${severity}">${escape(finding.severity.replace("_", " "))}</span>
           <div>
             <code>${escape(finding.code)}</code>${lint}
             <p>${escape(finding.detail)}</p>
           </div>
         </li>`,
      );
    }
    parts.push("</ul>");
  }

  reportEl.className = "report";
  reportEl.innerHTML = parts.join("");
}

function showError(message: string): void {
  reportEl.className = "report";
  reportEl.innerHTML = `<div class="error">${escape(message)}</div>`;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function networkName(network: Report["network"]): string {
  if (typeof network === "string") {
    if (network === "main") return "mainnet";
    if (network === "test") return "testnet";
    return network;
  }
  return `unknown network (coin type ${network.other})`;
}

function zec(zats: number): string {
  const whole = Math.floor(zats / 100_000_000);
  const fraction = String(zats % 100_000_000).padStart(8, "0");
  return `${whole}.${fraction} ZEC`;
}

function shorten(address: string): string {
  return address.length <= 44 ? address : `${address.slice(0, 24)}…${address.slice(-12)}`;
}

function escape(text: string): string {
  return text.replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character,
  );
}

void main();

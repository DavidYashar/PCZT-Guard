# Testnet end-to-end test

One run, start to finish: a wallet builds a payment, PCZT Guard verifies it, a signer signs
it, and the transaction confirms on Testnet.

**Every step below is a single line you can paste into PowerShell as-is.** If a block were
split across lines, pasting would concatenate them and fail.

**Do not pause between steps 3 and 10.** A PCZT expires about four minutes after it is built.

> **This runbook records a run that actually happened**, on Windows with PowerShell, so the
> paths below are the ones that were used (`C:\zcash-e2e` for the scratch directory, the
> repository where it was cloned). Step 0 sets them as variables — change those four values and
> the rest of the runbook follows. The one Windows-specific hazard is that `>` writes UTF-16,
> which is why step 7 pipes through `Set-Content` instead; both binaries also read UTF-16
> correctly, so a redirect works too.

---

## What you need

| Thing | Value |
|---|---|
| `zcash-devtool` | installed and on PATH |
| Wallet with funds | `C:\zcash-e2e\w1` (a scratch directory you choose) |
| This repository | the directory you cloned `pczt-guard` into |

You supply two things during the run, both generated for you: a **payee address** (step 2) and
a **mnemonic file** (step 7). Nothing is typed by hand.

---

## Step 0 — set the paths

```powershell
Set-Location C:\zcash-e2e; $repo = "C:\Users\yasha\vsCode\zcashProjectHackathon"; $wallet = "C:\zcash-e2e\w1"; $identity = "C:\zcash-e2e\id.txt"
```

*Does:* stores three paths in variables so later commands need no editing. *Provide:* nothing.
*Expect:* no output. If a later step says "cannot find path", this line was run in a different
window.

---

## Step 1 — confirm the coins are spendable

```powershell
zcash-devtool wallet -w $wallet sync; zcash-devtool wallet -w $wallet balance
```

*Does:* `sync` scans new blocks; `balance` shows the total **and** what is spendable.
*Provide:* nothing. *Expect:* `Ironwood Spendable` above `0.02000000 TAZ`. If it is
`0.00000000`, the notes need more confirmations — wait a minute and run this line again.

---

## Step 2 — choose the payee address

```powershell
$out = zcash-devtool wallet -w $wallet generate-address 2>$null | Out-String; $payee = [regex]::Match($out, 'utest1[0-9a-z]+').Value; $payee
```

*Does:* asks the wallet for a fresh address and keeps it in `$payee`. *Provide:* nothing —
paying yourself is deliberate. *Expect:* one line starting with `utest1`.

---

## Step 3 — build the PCZT

```powershell
zcash-devtool pczt -w $wallet create --address $payee --value 1000000 --output t1.pczt; Get-ChildItem t1.pczt | Select-Object Name, Length
```

*Does:* builds an unsigned, unproven transaction paying **0.01 TAZ** (`--value` is zatoshi).
*Provide:* `$payee` from step 2. *Expect:* `t1.pczt`, roughly 5,000 bytes.

---

## Step 4 — Guard's default verdict

```powershell
Set-Location $repo; cargo run -q -p pczt-guard-cli -- check C:\zcash-e2e\t1.pczt
```

*Does:* re-derives every commitment and compares the address shown to the address paid.
*Provide:* nothing. *Expect:* `CANNOT VERIFY`, exit code 2, one `unverified UnlabeledOutput`,
and your payment line marked `[verified]`. That is correct: the change output has no label and
Guard will not call that safe.

---

## Step 4b — the same PCZT, with the wallet's own viewing key

```powershell
cd $repo; cargo run -q -p pczt-guard-signer -- --mnemonic-file C:\zcash-e2e\phrase.txt --print-ufvk > C:\zcash-e2e\ufvk.txt; cargo run -q -p pczt-guard-cli -- check C:\zcash-e2e\t1.pczt --ufvk-file C:\zcash-e2e\ufvk.txt
```

*Does:* derives the wallet's *viewing* key (it cannot spend) and uses it to trial-decrypt
every output. *Provide:* the phrase file from step 7 — run step 7 first if you have not.
*Expect:* `SAFE`, exit code 0, your change marked `[change, proven]`, and an
`info OwnedChange` line per proven output.

This is the difference the viewing key makes: step 4 could only say "I cannot tell whether
that unlabelled output is yours", and this step proves it. An output that does *not* decrypt
would come back `unsafe NotOurOutput`, which is the hidden-output attack caught outright.

---

## Step 5 — the same PCZT, allowing unlabelled change

```powershell
cargo run -q -p pczt-guard-cli -- check C:\zcash-e2e\t1.pczt --allow-unlabeled-change
```

*Does:* identical, except an unlabelled output is information instead of a blocker.
*Provide:* nothing. *Expect:* `SAFE`, exit code 0, one `info UnlabeledOutput`.

**If step 4 or 5 prints a line beginning `unsafe`, stop and send it to me** — that would be a
real contradiction, which is what this test looks for.

---

## Step 6 — save the JSON report

```powershell
cargo run -q -p pczt-guard-cli -- check C:\zcash-e2e\t1.pczt --json > C:\zcash-e2e\guard-report.json; Get-Content C:\zcash-e2e\guard-report.json | Select-Object -First 3
```

*Does:* writes the full report as JSON. *Provide:* nothing. *Expect:* the first lines show
`"verdict": "CANNOT_VERIFY"` and `"network": "test"`.

---

## Step 7 — export the mnemonic

```powershell
Set-Location C:\zcash-e2e; zcash-devtool wallet -w $wallet display-mnemonic -i $identity --enable | Set-Content phrase.txt; (Get-Content phrase.txt -Raw).Trim().Split(' ').Count
```

*Does:* decrypts the recovery phrase into `phrase.txt`. `--enable` is required — without it the
tool refuses. *Provide:* nothing. *Expect:* `24` (the word count; the words are not printed).

`phrase.txt` is a secret even on Testnet. Step 11 deletes it.

---

## Step 8 — sign the PCZT

```powershell
cd $repo; cargo run -q -p pczt-guard-signer -- --pczt C:\zcash-e2e\t1.pczt --mnemonic-file C:\zcash-e2e\phrase.txt --network test --output C:\zcash-e2e\t1signed.pczt; Get-ChildItem C:\zcash-e2e\t1.pczt, C:\zcash-e2e\t1signed.pczt | Select-Object Name, Length
```

*Does:* derives your spending key, runs PCZT Guard with the same key, and only then signs the
spend that belongs to it. This step exists because `zcash-devtool pczt sign` cannot sign
Ironwood spends — it has no Ironwood path and silently writes an unchanged file.
*Provide:* the two paths above. *Expect:* a first line
`pczt-guard-signer: PCZT Guard says SAFE (n external payment(s), m output(s) proven to be this
wallet's own)`, then `pczt-guard-signer: signed 1 spend(s)`, and `t1signed.pczt` **exactly 64
bytes larger**. Equal sizes means nothing was signed.

If Guard says `UNSAFE`, the signer refuses and no file is written — that is the feature
working, not a failure. `CANNOT VERIFY` also refuses unless you add `--allow-unverified`.

---

## Step 9 — prove

```powershell
zcash-devtool pczt prove C:\zcash-e2e\t1signed.pczt --output C:\zcash-e2e\t1proven.pczt; Get-ChildItem C:\zcash-e2e\t1proven.pczt | Select-Object Name, Length
```

*Does:* builds the zero-knowledge proofs (10–30 s). *Provide:* nothing. *Expect:*
`t1proven.pczt`, roughly 12,000–26,000 bytes.

---

## Step 10 — broadcast

```powershell
zcash-devtool pczt -w $wallet send C:\zcash-e2e\t1proven.pczt
```

*Does:* extracts the transaction and submits it. *Provide:* nothing. *Expect:* a 64-character
transaction id, printed last. **Copy it.**

If it says *"greater than its expiry Height"*, more than four minutes passed since step 3 —
redo steps 3 to 10 in one pass.

---

## Step 11 — delete the mnemonic file

```powershell
Remove-Item C:\zcash-e2e\phrase.txt; Test-Path C:\zcash-e2e\phrase.txt
```

*Does:* removes the phrase from disk. *Expect:* `False`. You will not need it again — the
wallet directory *is* the wallet.

---

## Step 12 — confirm it landed

```powershell
zcash-devtool wallet -w $wallet sync; zcash-devtool wallet -w $wallet balance
```

*Does:* waits for the next block and re-reads the wallet. *Expect:* a balance about **0.0001
TAZ lower** than step 1 — the fee; the payment returns to you because the payee was your own
address.

`Ironwood Spendable` will read lower than `Balance` for a minute: the new notes are not
confirmed yet. Normal.

---

## Result of the reference run

This runbook was executed verbatim by a second person on a second wallet, on 21 October 2026,
`zcash-devtool 0.1.0` (git `0b3436bb`), Testnet.

| Step | Observed |
|---|---|
| 1 | Balance 0.99965 TAZ; Ironwood Spendable 0.98965 TAZ; height 4525300 |
| 2 | payee `utest1a6jt205sk2048zlmp4mtceme0984z2uf34axar8p7ja53aqp9dhfex9fl6kzykgp6fmnu2gaazu38tq0r6f9qtt05pzuenrjv587f6sh` |
| 3 | `t1.pczt` 4,953 bytes |
| 4 | `CANNOT VERIFY`, exit 2, payment `[verified]`, one `unverified UnlabeledOutput` |
| 5 | `SAFE`, exit 0, one `info UnlabeledOutput` |
| 6 | `"verdict": "CANNOT_VERIFY"`, `"network": "test"` |
| 7 | 24 words |
| 8 | `signed 1 spend(s)`; 4,953 → **5,017 bytes (+64)** |
| 9 | `t1proven.pczt` 12,283 bytes |
| 10 | `e930ce6faa443199b8d054a99ee812718fca5c007af9310a5f8d9f9db0ae3b22` |
| 11 | `phrase.txt` removed |
| 12 | **Mined at height 4,525,306**; spendable 75,221,250 plus 23,733,750 change pending confirmation |

No `unsafe` finding at any point: Guard agreed with a transaction it did not build, and the
transaction it approved confirmed.

> `wallet sync` also prints a raw `WalletSummary { … }` debug dump. Read the numbers from the
> `balance` output below it; the dump is noisy but harmless.

---

## What to send back
```text
1.  step 1 — full `balance` output
2.  step 2 — the payee address
3.  step 3 — size of t1.pczt
4.  step 4 — full output + $LASTEXITCODE
5.  step 5 — full output + $LASTEXITCODE
6.  step 6 — C:\zcash-e2e\guard-report.json
7.  step 8 — full output + both file sizes
8.  step 9 — size of t1proven.pczt
9.  step 10 — the txid
10. step 12 — full `balance` output
11. anything unexpected — the exact text
```

Never send `phrase.txt` or `id.txt`. You may send `t1.pczt`; a PCZT contains no keys.

---

## If something fails

| Step | Symptom | Meaning | Do this |
|---|---|---|---|
| 0 | `positional parameter cannot be found` | the line was pasted with newlines inside it | paste it as one line, as written |
| 1 | `Ironwood Spendable` is 0 | notes lack confirmations | wait a minute, re-run the line |
| 3 | `Insufficient balance` | same, or an unmined tx reserved a note | `sync`, wait ~3 blocks, retry |
| 7 | `cannot find path` | `$identity` not set | re-run step 0 in this window |
| 8 | `stream did not contain valid UTF-8` | stale binary | `cargo build -p pczt-guard-signer`, retry |
| 8 | file size unchanged | the spend is not from that phrase | confirm you used wallet `w1`'s identity |
| 10 | `greater than its expiry Height` | more than four minutes elapsed | redo 3 → 10 in one pass |
| 10 | `MissingSpendAuthSig` | `t1.pczt` was sent instead of `t1proven.pczt` | send the proven file |
| 4 or 5 | a line starting `unsafe` | **real finding** | stop, send the output |

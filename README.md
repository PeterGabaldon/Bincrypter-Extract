# bincrypter-extract

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

Statically extract the payload embedded in a [bincrypter](https://github.com/hackerschoice/bincrypter)-obfuscated shell script.

bincrypter wraps an ELF binary or a shell script into a self-decrypting `/bin/sh`
script. Malware families — notably **gsocket / gs-netcat** implants deployed via
`deploy.sh` — use it to ship a fileless dropper. This tool unwraps it **without
executing anything**.

## Install

```sh
git clone https://github.com/<you>/bincrypter-extract
cd bincrypter-extract
pip install cryptography          # the only dependency
```

## Usage

```sh
python3 bincrypter_extract.py suspicious.sh -o payload.bin
```

```
[*] suspicious.sh  (1094250 bytes, sha256 532015ceef91eff7...)
  stub          2823 bytes
  S (salt)      l03gq2AyAmm8rJYT
  password      CHzBoZgxTSwW2oSS
  R (padding)   12920
  ciphertext    1069776 bytes
  decrypted     1069762 bytes
  inflated      1084800 bytes
[+] payload: ELF 64-bit x86-64, 1084800 bytes
[+] sha256:  89e906327d8e85067e16f3eb077a4a891fd01773460363b235918035314703ea
[+] wrote payload.bin
```

Options:

| Flag | Meaning |
|---|---|
| `-o, --output` | write the payload to a file (otherwise piped to stdout when redirected) |
| `-p, --password` | supply the password for `BC_LOCK`'ed stubs or when `P=` is absent |
| `-q, --quiet` | suppress progress output |

## How it works

| Layer | bincrypter does | this tool undoes |
|---|---|---|
| 1 | splices empty command substitutions (`` `! :&&<BS>#` ``, `` `:||<BEL>` ``) inside keywords so `eval`/`openssl`/`perl` never appear literally | strips every `` `...` `` run |
| 2 | hides the loader's base64 among random non-printable bytes | keeps only ASCII `0x20–0x7E`, takes the longest base64 run |
| 3 | stores `P` (password), `S` (salt), `C` (AES blob that `eval`s to `R`) | decodes `P`, decrypts `C` with key `C-{S}-{P}`, reads `R` |
| 4 | escapes the ciphertext `B`→`B2`, `NUL`→`B1`, `LF`→`B3` so the file stays a single NUL-free line | reverses the substitutions (`B2` last) |
| 5 | AES-256-CBC with `EVP_BytesToKey(sha256, no salt)` over key material `{S}-{P}` | same derivation, decrypts, strips PKCS#7 |
| 6 | prepends `R` random bytes, then gzip | skips `R`, inflates |

The number of lines and bytes the loader discards is parsed from the recovered
stub rather than hardcoded, so the tool tracks upstream changes to the hook.

## Safety

The sample is **never executed**. There is no `subprocess`, no `eval`, no shelling
out to `openssl`/`perl`/`gunzip` — every step is pure Python. Safe to run on an
analysis workstation, though the extracted payload is of course still live malware.

## Limitations

- Only `-md sha256 -nosalt` AES-256-CBC stubs (all bincrypter versions to date).
- `BC_LOCK`'ed stubs need `--password`; the lock's host-binding is not brute-forced.
- The payload is returned as-is. If it is a UPX-packed ELF with stripped magics,
  `upx -d` will refuse it — that is a separate unpacking problem.

## License

MIT — see [LICENSE](LICENSE).

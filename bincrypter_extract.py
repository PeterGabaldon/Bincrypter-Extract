#!/usr/bin/env python3
"""Extract the payload embedded in a bincrypter-obfuscated shell script.

bincrypter (https://github.com/hackerschoice/bincrypter) wraps an ELF binary or
a shell script into a self-decrypting /bin/sh script.  This tool reverses that
wrapping statically -- nothing from the sample is ever executed.

Layer by layer:

  1. line 2 is obfuscated with empty command substitutions (`! :&&<BS>#` and
     `:||<BEL>`) spliced inside keywords; stripping them recovers the loader
  2. the loader base64 is hidden among random non-printable bytes
  3. the decoded stub carries P (password), S (salt) and C (an encrypted blob
     that eval()s to R, the length of a random prefix)
  4. the payload is the rest of the file, escaped B->B2, NUL->B1, LF->B3,
     then AES-256-CBC encrypted, then prefixed with R random bytes, then gzip
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import re
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    sys.exit("ERROR: missing dependency. Install with:  pip install cryptography")

__version__ = "1.0.0"

# Empty command substitutions used by bincrypter's _bc_obbell().
_BACKTICK = re.compile(rb"`[^`]*`")
_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")
# '<>;<>;read(STDIN,$_,1);' -- how many lines and bytes the hook discards.
_SKIP = re.compile(rb"((?:<>;)+)read\(STDIN,\\?\$_,(\d+)\)")


class ExtractError(Exception):
    pass


def evp_bytestokey(password: bytes, key_len: int = 32, iv_len: int = 16):
    """OpenSSL EVP_BytesToKey with -md sha256 -nosalt, iteration count 1."""
    out = b""
    prev = b""
    while len(out) < key_len + iv_len:
        prev = hashlib.sha256(prev + password).digest()
        out += prev
    return out[:key_len], out[key_len:key_len + iv_len]


def aes_cbc_decrypt(data: bytes, passphrase: bytes) -> bytes:
    key, iv = evp_bytestokey(passphrase)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = dec.update(data) + dec.finalize()
    if not out:
        raise ExtractError("AES produced no output")
    pad = out[-1]
    if 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad:
        out = out[:-pad]
    return out


def deobfuscate_loader(blob: bytes) -> bytes:
    """Strip the empty command substitutions from the loader line."""
    return _BACKTICK.sub(b"", blob)


def recover_stub(data: bytes) -> bytes:
    """Recover the plaintext bincrypter stub from the head of the script."""
    head = data[:data.find(b"\n", data.find(b"\n") + 1) + 1] or data[:65536]
    clean = deobfuscate_loader(head)
    printable = bytes(c for c in clean if 0x20 <= c < 0x7F)
    runs = _B64_RUN.findall(printable)
    if not runs:
        raise ExtractError("no base64 loader blob found (not a bincrypter script?)")
    for candidate in sorted(runs, key=len, reverse=True):
        try:
            stub = base64.b64decode(candidate + b"=" * (-len(candidate) % 4))
        except Exception:
            continue
        if b"openssl" in stub and (b"_bc_dec" in stub or b"gunzip" in stub):
            return stub
    raise ExtractError("base64 blob did not decode to a bincrypter stub")


def parse_stub(stub: bytes) -> dict:
    """Pull P / S / C and the hook's skip counts out of the stub."""
    text = stub.decode("latin1")

    def grab(name):
        m = re.search(rf"^{name}=['\"]?([A-Za-z0-9+/=]*)['\"]?\s*$", text, re.M)
        return m.group(1) if m else None

    info = {"P": grab("P"), "S": grab("S"), "C": grab("C"),
            "locked": bool(re.search(r"^BCV=", text, re.M))}
    m = _SKIP.search(stub)
    info["skip_lines"] = m.group(1).count(b"<>;") if m else 2
    info["skip_bytes"] = int(m.group(2)) if m else 1
    return info


def resolve_password(info: dict, override: str | None) -> bytes:
    if override is not None:
        return override.encode()
    if info["locked"]:
        raise ExtractError("stub is BC_LOCK'ed; supply the password with --password")
    if not info["P"]:
        raise ExtractError("no embedded password; supply one with --password")
    return base64.b64decode(info["P"]).rstrip(b"\n")


def resolve_offset(info: dict, password: bytes) -> int:
    """Decrypt C to recover R, the random-prefix length."""
    if not info["C"]:
        return 0
    key = f"C-{info['S']}-{password.decode('latin1')}".encode()
    try:
        cfg = aes_cbc_decrypt(base64.b64decode(info["C"]), key)
    except Exception as exc:
        raise ExtractError(f"could not decrypt C (wrong password?): {exc}") from exc
    m = re.search(rb"R=(\d+)", cfg)
    if not m:
        raise ExtractError(f"C decrypted but has no R=: {cfg[:80]!r}")
    return int(m.group(1))


def unescape(payload: bytes) -> bytes:
    """Undo B->B2, NUL->B1, LF->B3.  Order matters: B2 must go last."""
    return payload.replace(b"B3", b"\n").replace(b"B1", b"\x00").replace(b"B2", b"B")


def extract(data: bytes, password: str | None = None, verbose=lambda *_: None) -> bytes:
    stub = recover_stub(data)
    info = parse_stub(stub)
    verbose(f"  stub          {len(stub)} bytes"
            f"{' (BC_LOCK)' if info['locked'] else ''}")
    verbose(f"  S (salt)      {info['S']}")

    pw = resolve_password(info, password)
    verbose(f"  password      {pw.decode('latin1')}")

    offset = resolve_offset(info, pw)
    verbose(f"  R (padding)   {offset}")

    pos = 0
    for _ in range(info["skip_lines"]):
        nxt = data.find(b"\n", pos)
        if nxt < 0:
            raise ExtractError("script has fewer lines than the hook expects")
        pos = nxt + 1
    pos += info["skip_bytes"]

    body = unescape(data[pos:])
    verbose(f"  ciphertext    {len(body)} bytes")

    key = f"{info['S']}-{pw.decode('latin1')}".encode()
    plain = aes_cbc_decrypt(body, key)
    verbose(f"  decrypted     {len(plain)} bytes")

    stream = plain[offset:]
    if stream[:2] != b"\x1f\x8b":
        raise ExtractError(
            f"no gzip magic at offset {offset} (got {stream[:2].hex()}) -- wrong password?")
    out = gzip.decompress(stream)
    verbose(f"  inflated      {len(out)} bytes")
    return out


def describe(blob: bytes) -> str:
    if blob[:4] == b"\x7fELF":
        bits = {1: "32-bit", 2: "64-bit"}.get(blob[4], "?")
        machine = {0x3E: "x86-64", 0xB7: "aarch64", 0x28: "arm",
                   0x03: "i386", 0x08: "mips"}.get(
                       int.from_bytes(blob[18:20], "little"), "?")
        return f"ELF {bits} {machine}"
    if blob[:2] == b"#!":
        return "shell script"
    return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract the payload embedded in a bincrypter shell script.")
    ap.add_argument("script", help="the bincrypter-wrapped .sh file")
    ap.add_argument("-o", "--output", help="write the payload here")
    ap.add_argument("-p", "--password", help="password (if not embedded / BC_LOCK'ed)")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print errors")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    log = (lambda *a: None) if args.quiet else (lambda *a: print(*a))

    try:
        data = open(args.script, "rb").read()
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    log(f"[*] {args.script}  ({len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()})")
    try:
        payload = extract(data, args.password, verbose=log)
    except ExtractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    log(f"[+] payload: {describe(payload)}, {len(payload)} bytes")
    log(f"[+] sha256:  {hashlib.sha256(payload).hexdigest()}")

    if args.output:
        with open(args.output, "wb") as fh:
            fh.write(payload)
        log(f"[+] wrote {args.output}")
    elif not sys.stdout.isatty():
        sys.stdout.buffer.write(payload)
    else:
        log("[!] no -o given and stdout is a tty; payload not written")
    return 0


if __name__ == "__main__":
    sys.exit(main())

import hashlib


def is_valid_pow(email: str, github_url: str, nonce: int) -> bool:
    data = (
        email.encode("utf-8")
        + b"\n"
        + github_url.encode("utf-8")
        + b"\n"
        + nonce.to_bytes(8, "big")
    )

    digest = hashlib.sha256(data).digest()

    return digest[:3] == b"\x00\x00\x00" and digest[3] < 16


def mine(email: str, github_url: str) -> int:
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"

    nonce = 0

    while True:
        digest = hashlib.sha256(prefix + nonce.to_bytes(8, "big")).digest()

        if digest[:3] == b"\x00\x00\x00" and digest[3] < 16:
            return nonce

        if nonce % 1_000_000 == 0:
            print(f"Checked {nonce:,} nonces...")

        nonce += 1
"""암호/복호화 도구: Caesar, Vigenere, AES-256-GCM, RSA-OAEP, 하이브리드 키 교환.

사용법:
    python crypto_tool.py demo
    python crypto_tool.py caesar enc "Hello" --shift 3
    python crypto_tool.py vigenere dec "Khoor" --key KEY
    python crypto_tool.py aes enc "비밀 메시지"
    python crypto_tool.py aes dec <암호문> --key <키>
"""
import argparse
import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------- 1. 고전 암호 (교육용) ----------
def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    shift = -shift if decrypt else shift
    out = []
    for ch in text:
        if ch.isascii() and ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    shifts = [ord(k.lower()) - ord("a") for k in key if k.isalpha()]
    if not shifts:
        raise ValueError("키는 알파벳을 1글자 이상 포함해야 합니다.")
    out, i = [], 0
    for ch in text:
        if ch.isascii() and ch.isalpha():
            s = -shifts[i % len(shifts)] if decrypt else shifts[i % len(shifts)]
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + s) % 26 + base))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


# ---------- 2. AES-256-GCM (대칭키) ----------
def aes_generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    nonce = os.urandom(12)  # 매 암호화마다 새 nonce
    return nonce + AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)


def aes_decrypt(blob: bytes, key: bytes) -> str:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")  # 변조 시 예외


# ---------- 3. RSA-2048 (공개키) ----------
def rsa_generate_keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def rsa_encrypt(data: bytes, public_key) -> bytes:
    return public_key.encrypt(data, _OAEP)


def rsa_decrypt(data: bytes, private_key) -> bytes:
    return private_key.decrypt(data, _OAEP)


def export_public_pem(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


# ---------- 4. 하이브리드 키 교환 (RSA로 AES 키 전달) ----------
def hybrid_demo(message: str, verbose: bool = True) -> str:
    b64 = lambda b: base64.b64encode(b).decode()
    log = print if verbose else (lambda *a, **k: None)

    log("[수신자] RSA 키 쌍 생성 → 공개키 공개")
    bob_private, bob_public = rsa_generate_keypair()

    log("[송신자] 일회용 AES 키 생성 후 메시지 암호화")
    session_key = aes_generate_key()
    ciphertext = aes_encrypt(message, session_key)
    log("  평문      :", message)
    log("  암호문    :", b64(ciphertext))

    log("[송신자] AES 키를 수신자의 RSA 공개키로 암호화하여 전송")
    wrapped_key = rsa_encrypt(session_key, bob_public)
    log("  암호화된 키:", b64(wrapped_key)[:60] + "...")

    log("[수신자] RSA 개인키로 AES 키 복원 → 메시지 복호화")
    recovered_key = rsa_decrypt(wrapped_key, bob_private)
    plaintext = aes_decrypt(ciphertext, recovered_key)
    log("  복호화 결과:", plaintext)
    log("  일치 여부  :", plaintext == message)
    return plaintext


# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(description="암호/복호화 도구")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("demo", help="AES + RSA 하이브리드 키 교환 시연").add_argument(
        "--msg", default="안녕하세요, 이것은 비밀 메시지입니다!"
    )

    for name in ("caesar", "vigenere", "aes"):
        sp = sub.add_parser(name)
        sp.add_argument("mode", choices=["enc", "dec"])
        sp.add_argument("text")
        sp.add_argument("--shift", type=int, default=3)
        sp.add_argument("--key", help="vigenere: 문자열 키 / aes: base64 키")

    args = p.parse_args()

    if args.cmd == "demo":
        hybrid_demo(args.msg)
    elif args.cmd == "caesar":
        print(caesar(args.text, args.shift, args.mode == "dec"))
    elif args.cmd == "vigenere":
        print(vigenere(args.text, args.key or "KEY", args.mode == "dec"))
    elif args.cmd == "aes":
        if args.mode == "enc":
            key = base64.b64decode(args.key) if args.key else aes_generate_key()
            print("키    :", base64.b64encode(key).decode())
            print("암호문:", base64.b64encode(aes_encrypt(args.text, key)).decode())
        else:
            key = base64.b64decode(args.key)
            print(aes_decrypt(base64.b64decode(args.text), key))


if __name__ == "__main__":
    main()

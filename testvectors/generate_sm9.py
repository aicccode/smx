#!/usr/bin/env python3
"""Generate the shared SM9 test vectors for every SMX language implementation.

Values come from ``sm9_ref.py`` (plain Python integers, hashlib SM3, OpenSSL SM4), which
does not import the SMX library. Before writing anything, the reference is checked
against every worked example in GB/T 38635.5 (doc/SM9.pdf, part 5, appendices A to D).

Usage: python3 generate_sm9.py > sm9-vectors.json

Encodings (lowercase hex everywhere):
  scalar            32 bytes big endian
  G1 point          04 || x || y                       (65 bytes)
  G2 point          04 || x1 || x0 || y1 || y0         (129 bytes, high Fq2 component first)
  signature         h || S, S a G1 point               (97 bytes)
  ciphertext        C1 || C3 || C2, C1 a G1 point      (65 + 32 + len(C2) bytes)
  KEM ciphertext    C, a G1 point
"""

from __future__ import annotations

import json
import sys

import sm9_ref as R
from sm9_ref import Q


def x(v: int) -> str:
    return v.to_bytes(32, "big").hex()


def std(s: str) -> str:
    return "".join(s.split()).lower()


HID_SIGN, HID_EXCH, HID_ENC = 1, 2, 3


def check_standard() -> dict:
    """Appendices A-D of GB/T 38635.5. Raises AssertionError on any mismatch."""
    out = {}

    # A: signature
    ks = 0x0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4
    ppub_s = R.g2_mul(ks, R.P2)
    ds = R.sign_user_key(ks, b"Alice", HID_SIGN)
    r = 0x033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE
    msg = b"Chinese IBS standard"
    sig = R.sign(msg, ds, ppub_s, r)
    assert R.g2_to_bytes(ppub_s).hex()[2:130] == std(
        "9F64080B 3084F733 E48AFF4B 41B56501 1CE0711C 5E392CFB 0AB1B679 1B94C408"
        "29DBA116 152D1F78 6CE843ED 24A3B573 414D2177 386A92DD 8F14D656 96EA5E32"
    )
    assert R.g2_to_bytes(ppub_s).hex()[130:] == std(
        "69850938 ABEA0112 B57329F4 47E3A0CB AD3E2FDB 1A77F335 E89E1408 D0EF1C25"
        "41E00A53 DDA532DA 1A7CE027 B7A46F74 1006E85F 5CDFF073 0E75C05F B4E3216D"
    )
    assert R.g1_to_bytes(ds).hex() == "04" + std(
        "A5702F05 CF131530 5E2D6EB6 4B0DEB92 3DB1A0BC F0CAFF90 523AC875 4AA69820"
        "78559A84 4411F982 5C109F5E E3F52D72 0DD01785 392A727B B1556952 B2B013D3"
    )
    g = R.pairing(R.P1, ppub_s)
    assert R.f12_to_bytes(g).hex().startswith(
        std("4E378FB5 561CD066 8F906B73 1AC58FEE 25738EDF 09CADC7A 29C0ABC0 177AEA6D")
    )
    assert R.f12_to_bytes(g).hex().endswith(
        std("AAB9F06A 4EEBA432 3A7833DB 202E4E35 639D93FA 3305AF73 F0F071D7 D284FCFB")
    )
    assert sig.hex() == std(
        "823C4B21 E4BD2DFE 1ED92C60 6653E996 66856315 2FC33F55 D7BFBB9B D9705ADB"
        "04 73BF9692 3CE58B6A D0E13E96 43A406D8 EB98417C 50EF1B29 CEF9ADB4 8B6D598C"
        "856712F1 C2E0968A B7769F42 A99586AE D139D5B8 B3E15891 827CC2AC ED9BAA05"
    )
    assert R.verify(msg, sig, b"Alice", HID_SIGN, ppub_s)
    out["sign"] = {
        "source": "GB/T 38635.5 appendix A",
        "master_private_key": x(ks),
        "master_public_key": R.g2_to_bytes(ppub_s).hex(),
        "user_id": "Alice",
        "hid": HID_SIGN,
        "user_private_key": R.g1_to_bytes(ds).hex(),
        "message": msg.decode(),
        "r": x(r),
        "pairing_g": R.f12_to_bytes(g).hex(),
        "signature": sig.hex(),
    }

    # B: key exchange
    ke = 0x02E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F
    ppub_e = R.g1_mul(ke, R.P1)
    assert R.g1_to_bytes(ppub_e).hex() == "04" + std(
        "91745426 68E8F14A B273C094 5C3690C6 6E5DD096 78B86F73 4C435056 7ED06283"
        "54E598C6 BF749A3D ACC9FFFE DD9DB686 6C50457C FC7AA2A4 AD65C316 8FF74210"
    )
    de_a = R.enc_user_key(ke, b"Alice", HID_EXCH)
    de_b = R.enc_user_key(ke, b"Bob", HID_EXCH)
    assert R.g2_to_bytes(de_a).hex()[2:66] == std(
        "0FE8EAB3 95199B56 BF1D75BD 2CD610B6 424F08D1 092922C5 882B52DC D6CA832A"
    )
    assert R.g2_to_bytes(de_b).hex()[2:66] == std(
        "74CCC3AC 9C383C60 AF083972 B96D05C7 5F12C890 7D128A17 ADAFBAB8 C5A4ACF7"
    )
    ra = 0x5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8
    rb = 0x018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE
    kx = R.exchange(b"Alice", b"Bob", HID_EXCH, ppub_e, de_a, de_b, ra, rb, 16)
    assert kx["RA"].hex() == "04" + std(
        "7CBA5B19 069EE66A A79D4904 13D11846 B9BA76DD 22567F80 9CF23B6D 964BB265"
        "A9760C99 CB6F7063 43FED056 37085864 958D6C90 902ABA7D 405FBEDF 7B781599"
    )
    assert kx["RB"].hex() == "04" + std(
        "861E9148 5FB7623D 2794F495 031A3559 8B493BD4 5BE37813 ABC710FC C1F34482"
        "32D906A4 69EBC121 6A802A70 52D5617C D430FB56 FBA729D4 1D9BD668 E9EB9600"
    )
    assert kx["SK"].hex() == std("C5C13A8F 59A97CDE AE64F16A 2272A9E7")
    assert kx["SB"].hex() == std(
        "3BB4BCEE 8139C960 B4D6566D B1E0D5F0 B2767680 E5E1BF93 4103E6C6 6E40FFEE"
    )
    assert kx["SA"].hex() == std(
        "195D1B72 56BA7E0E 67C71202 A25F8C94 FF824170 2C2F55D6 13AE1C6B 98215172"
    )
    out["exchange"] = {
        "source": "GB/T 38635.5 appendix B",
        "master_private_key": x(ke),
        "master_public_key": R.g1_to_bytes(ppub_e).hex(),
        "hid": HID_EXCH,
        "id_a": "Alice",
        "id_b": "Bob",
        "user_private_key_a": R.g2_to_bytes(de_a).hex(),
        "user_private_key_b": R.g2_to_bytes(de_b).hex(),
        "key_len": 16,
        "r_a": x(ra),
        "r_b": x(rb),
        "R_a": kx["RA"].hex(),
        "R_b": kx["RB"].hex(),
        "shared_key": kx["SK"].hex(),
        "s_b": kx["SB"].hex(),
        "s_a": kx["SA"].hex(),
    }

    # C: KEM
    ke = 0x01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22
    ppub_e = R.g1_mul(ke, R.P1)
    assert R.g1_to_bytes(ppub_e).hex() == "04" + std(
        "787ED7B8 A51F3AB8 4E0A6600 3F32DA5C 720B17EC A7137D39 ABC66E3C 80A892FF"
        "769DE617 91E5ADC4 B9FF85A3 1354900B 20287127 9A8C49DC 3F220F64 4C57A7B1"
    )
    de_b = R.enc_user_key(ke, b"Bob", HID_ENC)
    assert R.g2_to_bytes(de_b).hex()[2:66] == std(
        "94736ACD 2C8C8796 CC4785E9 38301A13 9A059D35 37B64141 40B2D31E ECF41683"
    )
    r = 0x74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722
    k, c = R.encapsulate(b"Bob", HID_ENC, ppub_e, 32, r)
    assert c.hex() == "04" + std(
        "1EDEE2C3 F4659144 91DE44CE FB2CB434 AB02C308 D9DC5E20 67B4FED5 AAAC8A0F"
        "1C9B4C43 5ECA35AB 83BB7341 74C0F78F DE81A533 74AFF3B3 602BBC5E 37BE9A4C"
    )
    assert k.hex() == std(
        "4FF5CF86 D2AD40C8 F4BAC98D 76ABDBDE 0C0E2F0A 829D3F91 1EF5B2BC E0695480"
    )
    cpt = (int.from_bytes(c[1:33], "big"), int.from_bytes(c[33:], "big"))
    assert R.decapsulate(cpt, b"Bob", de_b, 32) == k
    out["encapsulate"] = {
        "source": "GB/T 38635.5 appendix C",
        "master_private_key": x(ke),
        "master_public_key": R.g1_to_bytes(ppub_e).hex(),
        "user_id": "Bob",
        "hid": HID_ENC,
        "user_private_key": R.g2_to_bytes(de_b).hex(),
        "key_len": 32,
        "r": x(r),
        "ciphertext": c.hex(),
        "key": k.hex(),
    }

    # D: encryption (same master key and user key as C)
    r = 0xAAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C
    msg = b"Chinese IBE standard"
    ct_stream = R.encrypt(msg, b"Bob", HID_ENC, ppub_e, r, block=False)
    ct_block = R.encrypt(msg, b"Bob", HID_ENC, ppub_e, r, block=True)
    c1 = std(
        "24454711 64490618 E1EE2052 8FF1D545 B0F14C8B CAA44544 F03DAB5D AC07D8FF"
        "42FFCA97 D57CDDC0 5EA405F2 E586FEB3 A6930715 532B8000 759F1305 9ED59AC0"
    )
    assert ct_stream.hex() == "04" + c1 + std(
        "BA672387 BCD6DE50 16A158A5 2BB2E7FC 429197BC AB70B25A FEE37A2B 9DB9F367"
        "1B5F5B0E 95148968 2F3E64E1 378CDD5D A9513B1C"
    )
    assert ct_block.hex() == "04" + c1 + std(
        "FD3C98DD 92C44C68 332675A3 70CCEEDE 31E0C5CD 209C2576 01149D12 B394A2BE"
        "E05B6FAC 6F11B965 268C994F 00DBA7A8 BB00FD60 583546CB DF464925 0863F10A"
    )
    assert R.decrypt(ct_stream, b"Bob", de_b, block=False) == msg
    assert R.decrypt(ct_block, b"Bob", de_b, block=True) == msg
    out["encrypt"] = {
        "source": "GB/T 38635.5 appendix D; C1 carries the 04 prefix here",
        "master_private_key": x(ke),
        "master_public_key": R.g1_to_bytes(ppub_e).hex(),
        "user_id": "Bob",
        "hid": HID_ENC,
        "user_private_key": R.g2_to_bytes(de_b).hex(),
        "plaintext": msg.decode(),
        "r": x(r),
        "ciphertext_stream": ct_stream.hex(),
        "ciphertext_sm4": ct_block.hex(),
    }
    return out


def extra_cases() -> dict:
    """Additional deterministic vectors: other identities, lengths, binary data."""
    ks = 0x1F2E3D4C5B6A79880102030405060708090A0B0C0D0E0F101112131415161718
    ke = 0x2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F70819
    ppub_s = R.g2_mul(ks, R.P2)
    ppub_e = R.g1_mul(ke, R.P1)
    ids = ["", "a", "张三@example.com", "x" * 300]
    sign_cases = []
    for i, uid in enumerate(ids):
        ub = uid.encode()
        ds = R.sign_user_key(ks, ub, HID_SIGN)
        msg = bytes(range(256))[: [0, 1, 64, 255][i]] if i else b""
        r = (0x1234567 * (i + 3) ** 40 + i) % (R.N - 1) + 1
        sig = R.sign(msg, ds, ppub_s, r)
        assert R.verify(msg, sig, ub, HID_SIGN, ppub_s)
        sign_cases.append(
            {
                "user_id": uid,
                "user_private_key": R.g1_to_bytes(ds).hex(),
                "message_hex": msg.hex(),
                "r": x(r),
                "signature": sig.hex(),
            }
        )
    enc_cases = []
    for i, (uid, mlen) in enumerate([("Bob", 1), ("张三@example.com", 16), ("", 33), ("x" * 300, 100)]):
        ub = uid.encode()
        de = R.enc_user_key(ke, ub, HID_ENC)
        msg = bytes((7 * j + i) & 0xFF for j in range(mlen))
        r = (0x7654321 * (i + 5) ** 37 + i) % (R.N - 1) + 1
        cs = R.encrypt(msg, ub, HID_ENC, ppub_e, r, block=False)
        cb = R.encrypt(msg, ub, HID_ENC, ppub_e, r, block=True)
        assert R.decrypt(cs, ub, de, False) == msg and R.decrypt(cb, ub, de, True) == msg
        enc_cases.append(
            {
                "user_id": uid,
                "user_private_key": R.g2_to_bytes(de).hex(),
                "plaintext_hex": msg.hex(),
                "r": x(r),
                "ciphertext_stream": cs.hex(),
                "ciphertext_sm4": cb.hex(),
            }
        )
    kem_cases = []
    for i, klen in enumerate([1, 31, 33, 100]):
        uid = ["Bob", "", "张三@example.com", "Carol"][i]
        ub = uid.encode()
        de = R.enc_user_key(ke, ub, HID_ENC)
        r = (0x13579BDF * (i + 7) ** 35 + i) % (R.N - 1) + 1
        k, c = R.encapsulate(ub, HID_ENC, ppub_e, klen, r)
        kem_cases.append(
            {
                "user_id": uid,
                "user_private_key": R.g2_to_bytes(de).hex(),
                "key_len": klen,
                "r": x(r),
                "ciphertext": c.hex(),
                "key": k.hex(),
            }
        )
    kx_cases = []
    for i, (ia, ib, klen) in enumerate([("Alice", "Bob", 1), ("张三", "李四", 32), ("", "server", 64)]):
        da = R.enc_user_key(ke, ia.encode(), HID_EXCH)
        db = R.enc_user_key(ke, ib.encode(), HID_EXCH)
        ra = (0x2468ACE * (i + 11) ** 33 + i) % (R.N - 1) + 1
        rb = (0x1357BDF * (i + 13) ** 33 + i) % (R.N - 1) + 1
        kx = R.exchange(ia.encode(), ib.encode(), HID_EXCH, ppub_e, da, db, ra, rb, klen)
        kx_cases.append(
            {
                "id_a": ia,
                "id_b": ib,
                "user_private_key_a": R.g2_to_bytes(da).hex(),
                "user_private_key_b": R.g2_to_bytes(db).hex(),
                "key_len": klen,
                "r_a": x(ra),
                "r_b": x(rb),
                "R_a": kx["RA"].hex(),
                "R_b": kx["RB"].hex(),
                "shared_key": kx["SK"].hex(),
                "s_b": kx["SB"].hex(),
                "s_a": kx["SA"].hex(),
            }
        )
    # SM4 mode, empty message: encryption refuses it, but a ciphertext of one full padding
    # block is authentic and must decrypt to empty bytes.
    de = R.enc_user_key(ke, b"Bob", HID_ENC)
    r = 0x1234567890ABCDEF
    c1 = R.g1_mul(r, R.q_of(b"Bob", HID_ENC, ppub_e))
    w = R.f12_pow(R.pairing(ppub_e, R.P2), r)
    k = R.kdf(R.g1_xy(c1) + R.f12_to_bytes(w) + b"Bob", R.SM4_KEY_LEN + R.MAC_KEY_LEN)
    c2 = R.sm4_ecb(k[: R.SM4_KEY_LEN], b"")
    empty_ct = R.g1_to_bytes(c1) + R.sm3(c2 + k[R.SM4_KEY_LEN :]) + c2
    assert R.decrypt(empty_ct, b"Bob", de, True) == b""
    return {
        "sm4_empty_plaintext": {
            "user_id": "Bob",
            "user_private_key": R.g2_to_bytes(de).hex(),
            "ciphertext_sm4": empty_ct.hex(),
            "plaintext_hex": "",
        },
        "sign_master_private_key": x(ks),
        "sign_master_public_key": R.g2_to_bytes(ppub_s).hex(),
        "enc_master_private_key": x(ke),
        "enc_master_public_key": R.g1_to_bytes(ppub_e).hex(),
        "sign": sign_cases,
        "encrypt": enc_cases,
        "encapsulate": kem_cases,
        "exchange": kx_cases,
    }


def invalid_points() -> dict:
    """Encodings every decoder must reject."""
    g1 = R.g1_to_bytes(R.P1).hex()
    g2 = R.g2_to_bytes(R.P2).hex()
    q_hex = x(R.Q)
    # A point on the twist that is not in the order-N subgroup: find one by hashing x.
    xi = 1
    while True:
        xx = (xi, 1)
        rhs = R.f2_add(R.f2_mul(R.f2_mul(xx, xx), xx), R.B_TWIST)
        # sqrt in Fq2 by brute force exponent (q^2 + 7) / 16 does not apply; use norm trick.
        y = _f2_sqrt(rhs)
        if y is not None:
            pt = (xx, y)
            assert R.g2_on_curve(pt)
            if R.g2_mul(R.N, pt) is not None:
                break
        xi += 1
    off_subgroup = R.g2_to_bytes(pt).hex()
    return {
        "g1": [
            {"name": "empty", "value": ""},
            {"name": "infinity_00", "value": "00"},
            {"name": "compressed_prefix", "value": "02" + g1[2:66]},
            {"name": "wrong_prefix", "value": "05" + g1[2:]},
            {"name": "short", "value": g1[:-2]},
            {"name": "long", "value": g1 + "00"},
            {"name": "non_hex", "value": "zz" + g1[2:]},
            {"name": "not_on_curve", "value": g1[:-2] + ("00" if g1[-2:] != "00" else "01")},
            {"name": "x_equals_q", "value": "04" + q_hex + g1[66:]},
            {"name": "zero_point", "value": "04" + "00" * 64},
        ],
        "g2": [
            {"name": "empty", "value": ""},
            {"name": "wrong_prefix", "value": "05" + g2[2:]},
            {"name": "short", "value": g2[:-2]},
            {"name": "long", "value": g2 + "00"},
            {"name": "not_on_curve", "value": g2[:-2] + ("00" if g2[-2:] != "00" else "01")},
            {"name": "coordinate_equals_q", "value": "04" + q_hex + g2[66:]},
            {"name": "not_in_subgroup", "value": off_subgroup},
            {"name": "zero_point", "value": "04" + "00" * 128},
        ],
    }


def _f2_sqrt(a):
    """Square root in Fq2 (q = 1 mod 4 is false here: q = 1 mod 4? handled generically)."""
    # Norm method: for a = a0 + a1 u with u^2 = -2.
    a0, a1 = a
    if a1 == 0:
        s = _fq_sqrt(a0)
        if s is not None:
            return (s, 0)
        s = _fq_sqrt(a0 * pow(-2, Q - 2, Q) % Q)
        return None if s is None else (0, s)
    n = (a0 * a0 + 2 * a1 * a1) % Q
    sn = _fq_sqrt(n)
    if sn is None:
        return None
    for cand in (sn, (-sn) % Q):
        t = (a0 + cand) * pow(2, Q - 2, Q) % Q
        x0 = _fq_sqrt(t)
        if x0 is None or x0 == 0:
            continue
        x1 = a1 * pow(2 * x0, Q - 2, Q) % Q
        if R.f2_mul((x0, x1), (x0, x1)) == (a0 % Q, a1 % Q):
            return (x0, x1)
    return None


def _fq_sqrt(a):
    a %= Q
    if a == 0:
        return 0
    if pow(a, (Q - 1) // 2, Q) != 1:
        return None
    # Tonelli-Shanks
    s, qq = 0, Q - 1
    while qq % 2 == 0:
        qq //= 2
        s += 1
    z = 2
    while pow(z, (Q - 1) // 2, Q) != Q - 1:
        z += 1
    m, c, t, r = s, pow(z, qq, Q), pow(a, qq, Q), pow(a, (qq + 1) // 2, Q)
    while t != 1:
        i, tt = 0, t
        while tt != 1:
            tt = tt * tt % Q
            i += 1
        b = pow(c, 1 << (m - i - 1), Q)
        m, c, t, r = i, b * b % Q, t * b * b % Q, r * b % Q
    return r


def main() -> None:
    std_vectors = check_standard()
    data = {
        "_comment": (
            "SM9 test vectors, lowercase hex. G1 = 04||x||y, G2 = 04||x1||x0||y1||y0 "
            "(high Fq2 component first), GT = 384 bytes as in GB/T 38635.5. "
            "signature = h||S, ciphertext = C1||C3||C2 with C1 a G1 point, "
            "MAC key 32 bytes, SM4 mode is ECB with PKCS#7 as in the standard example. "
            "user_id strings are UTF-8. Generated by testvectors/generate_sm9.py."
        ),
        "params": {
            "q": x(R.Q),
            "n": x(R.N),
            "t": f"{R.T:x}",
            "b": 5,
            "P1": R.g1_to_bytes(R.P1).hex(),
            "P2": R.g2_to_bytes(R.P2).hex(),
            "hid_sign": HID_SIGN,
            "hid_exchange": HID_EXCH,
            "hid_encrypt": HID_ENC,
        },
        "standard": std_vectors,
        "extra": extra_cases(),
        "invalid_points": invalid_points(),
        "invalid_scalars": [
            {"name": "zero", "value": "00" * 32},
            {"name": "n", "value": x(R.N)},
            {"name": "n_plus_1", "value": x(R.N + 1)},
            {"name": "short", "value": "01" * 31},
            {"name": "long", "value": "01" * 33},
            {"name": "non_hex", "value": "zz" + "01" * 31},
        ],
        "max_valid_master_private_key": x(R.N - 1),
    }
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

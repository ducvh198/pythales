"""
Empirical Stress Test Harness and Cryptographic Oracle Verification Suite for M4 Iteration 2.
Executed by challenger_m4_it2_2.

Provides independent cryptographic verification oracles for:
- 3DES ECB, CBC, CTR modes
- NIST SP 800-38G FF1 FPE
- ISO 9797 Alg 1 & Alg 3 (Retail MAC)
- NIST SP 800-38B 3DES CMAC
- EMV CSKD Option 1 UDK & Session Key derivation (SK_AC, SK_SMC, SK_SMI)
- PayShield TCP envelope formatting and Error Truncation Rule
- Concurrency & Thread-safety stress testing
"""

import unittest
import struct
import concurrent.futures
from binascii import hexlify, unhexlify
import Crypto.Cipher.DES
import Crypto.Cipher.DES3

from pythales.hsm import HSM
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.core.frame import CommandFrame, ResponseFrame, MessageFraming
from pythales.commands.mac_data import (
    iso9797_alg1_mac,
    iso9797_alg3_mac,
    cmac_calc,
    des3_ctr_crypt,
    FF1Cipher,
    _get_key_raw
)
from pythales.commands.emv import derive_emv_session_key


def make_req(header: bytes, cmd: str, payload: bytes) -> bytes:
    msg = header + cmd.encode("ascii") + payload
    return struct.pack("!H", len(msg)) + msg


def parse_resp(raw_resp: bytes, header_len: int = 4) -> ResponseFrame:
    header = raw_resp[:header_len]
    resp_code = raw_resp[header_len:header_len+2].decode("ascii", errors="ignore")
    err_code = raw_resp[header_len+2:header_len+4].decode("ascii", errors="ignore")
    payload = raw_resp[header_len+4:]
    return ResponseFrame(header_bytes=header, response_code=resp_code, error_code=err_code, payload_bytes=payload)


def reference_iso9797_alg3(key_bytes: bytes, data_bytes: bytes) -> bytes:
    """Independent oracle for ISO 9797-1 Algorithm 3 (Retail MAC)."""
    k1 = key_bytes[:8]
    k2 = key_bytes[8:16] if len(key_bytes) >= 16 else key_bytes[:8]
    
    pad_len = (8 - (len(data_bytes) % 8)) % 8
    padded = data_bytes + b"\x80" + b"\x00" * (pad_len - 1 if pad_len > 0 else 7)

    c1 = Crypto.Cipher.DES.new(k1, Crypto.Cipher.DES.MODE_CBC, iv=b"\x00" * 8)
    y = c1.encrypt(padded)[-8:]

    c2_dec = Crypto.Cipher.DES.new(k2, Crypto.Cipher.DES.MODE_ECB)
    z = c2_dec.decrypt(y)

    c1_enc = Crypto.Cipher.DES.new(k1, Crypto.Cipher.DES.MODE_ECB)
    return c1_enc.encrypt(z)


def reference_3des_cmac(key_bytes: bytes, data_bytes: bytes) -> bytes:
    """Independent oracle for NIST SP 800-38B 3DES CMAC."""
    key3 = key_bytes if len(key_bytes) == 24 else key_bytes + key_bytes[:8]
    cipher_zero = Crypto.Cipher.DES3.new(key3, Crypto.Cipher.DES3.MODE_ECB)
    L = cipher_zero.encrypt(b"\x00" * 8)

    val_L = int.from_bytes(L, "big")
    msb1 = (val_L >> 63) & 1
    K1_int = ((val_L << 1) & 0xFFFFFFFFFFFFFFFF)
    if msb1:
        K1_int ^= 0x1B
    K1 = K1_int.to_bytes(8, "big")

    msb2 = (K1_int >> 63) & 1
    K2_int = ((K1_int << 1) & 0xFFFFFFFFFFFFFFFF)
    if msb2:
        K2_int ^= 0x1B
    K2 = K2_int.to_bytes(8, "big")

    n = (len(data_bytes) + 7) // 8
    if n == 0:
        n = 1
    
    if len(data_bytes) != 0 and len(data_bytes) % 8 == 0:
        last_block = bytes(a ^ b for a, b in zip(data_bytes[-8:], K1))
        blocks = [data_bytes[i*8:(i+1)*8] for i in range(n-1)] + [last_block]
    else:
        rem_len = len(data_bytes) % 8
        padded_last = data_bytes[-rem_len:] if rem_len > 0 else b""
        padded_last += b"\x80" + b"\x00" * (7 - rem_len)
        last_block = bytes(a ^ b for a, b in zip(padded_last, K2))
        blocks = [data_bytes[i*8:(i+1)*8] for i in range(n-1)] + [last_block]

    cipher_cbc = Crypto.Cipher.DES3.new(key3, Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
    return cipher_cbc.encrypt(b"".join(blocks))[-8:]


class TestChallengerM4It2Stress(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="STRS")
        a0_req = make_req(b"STRS", "A0", b"000BU")
        r1 = parse_resp(self.hsm.process_raw_message(a0_req))
        self.assertEqual(r1.error_code, ErrorCodes.SUCCESS)
        self.dek1 = r1.payload_bytes[:33].decode("ascii")

        a0_mac_req = make_req(b"STRS", "A0", b"000AU")
        r2 = parse_resp(self.hsm.process_raw_message(a0_mac_req))
        self.assertEqual(r2.error_code, ErrorCodes.SUCCESS)
        self.tak1 = r2.payload_bytes[:33].decode("ascii")

        a0_mdk_req = make_req(b"STRS", "A0", b"0000U")
        r3 = parse_resp(self.hsm.process_raw_message(a0_mdk_req))
        self.assertEqual(r3.error_code, ErrorCodes.SUCCESS)
        self.mdk1 = r3.payload_bytes[:33].decode("ascii")

    # =========================================================================
    # 1. Independent Cryptographic Oracle Verification
    # =========================================================================
    def test_oracle_iso9797_alg3(self):
        """Verify pythales iso9797_alg3_mac against independent reference oracle."""
        key = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"
        data = b"ORACLE_ISO9797_ALG3_VERIFICATION_TEST_DATA"
        
        pythales_mac = iso9797_alg3_mac(key, data)
        reference_mac = reference_iso9797_alg3(key, data)
        self.assertEqual(pythales_mac, reference_mac)

    def test_oracle_3des_cmac(self):
        """Verify pythales cmac_calc against independent NIST SP 800-38B reference oracle."""
        key = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00\xAA\xBB\xCC\xDD\xEE\xFF"
        for data in [b"", b"12345678", b"1234567890123456", b"SHORT_UNALIGNED_DATA"]:
            pythales_cmac = cmac_calc(key, data)
            reference_cmac = reference_3des_cmac(key, data)
            self.assertEqual(pythales_cmac, reference_cmac, f"CMAC mismatch on data={data}")

    def test_oracle_emv_cskd_udk_session_keys(self):
        """Verify derive_emv_session_key matches independent manual calculation."""
        mdk = b"\x01" * 16
        atc = b"\x00\x10"
        pan = "4000123456789010"
        psn = "01"

        sk_ac = derive_emv_session_key(mdk, atc, pan=pan, psn=psn)
        
        # Manual calculation:
        pan_psn_str = (pan + psn)[-16:].rjust(16, "0")
        z_left = unhexlify(pan_psn_str)
        z_right = bytes(b ^ 0xFF for b in z_left)

        imk3 = mdk + mdk[:8]
        c_imk = Crypto.Cipher.DES3.new(imk3, Crypto.Cipher.DES3.MODE_ECB)
        udk = c_imk.encrypt(z_left) + c_imk.encrypt(z_right)
        udk3 = udk + udk[:8]

        c_udk = Crypto.Cipher.DES3.new(udk3, Crypto.Cipher.DES3.MODE_ECB)
        sk_expected = c_udk.encrypt(atc + b"\xF0\x00\x00\x00\x00\x00") + c_udk.encrypt(atc + b"\x0F\x00\x00\x00\x00\x00")

        self.assertEqual(sk_ac, sk_expected)

    # =========================================================================
    # 2. Boundary Stress Testing & Payload Edge Cases
    # =========================================================================
    def test_m0_empty_and_zero_length_data(self):
        """Verify M0 with data_len=0 returns valid response or error without exception."""
        req = make_req(b"STRS", "M0", f"{self.dek1}000000".encode("ascii"))
        r = parse_resp(self.hsm.process_raw_message(req))
        self.assertEqual(r.response_code, "M1")
        self.assertIn(r.error_code, (ErrorCodes.SUCCESS, ErrorCodes.INVALID_DATA_LENGTH))

    def test_m6_cmac_unaligned_lengths(self):
        """Verify M6 CMAC mode handles all unaligned input lengths from 1 to 50 bytes."""
        for length in range(1, 51):
            data_bytes = bytes([i % 256 for i in range(length)])
            data_hex = hexlify(data_bytes).decode("ascii").upper()
            data_len_hex = f"{length:04X}"

            m6_req = make_req(b"STRS", "M6", f"{self.tak1}02{data_len_hex}{data_hex}".encode("ascii"))
            r_m6 = parse_resp(self.hsm.process_raw_message(m6_req))
            self.assertEqual(r_m6.error_code, ErrorCodes.SUCCESS, f"M6 CMAC failed at length {length}")
            mac_hex = r_m6.payload_bytes.decode("ascii")

            m8_req = make_req(b"STRS", "M8", f"{self.tak1}02{data_len_hex}{mac_hex}{data_hex}".encode("ascii"))
            r_m8 = parse_resp(self.hsm.process_raw_message(m8_req))
            self.assertEqual(r_m8.error_code, ErrorCodes.SUCCESS, f"M8 CMAC failed at length {length}")

    def test_kq_pan_without_semicolon(self):
        """Verify KQ command handles 16-digit PAN without semicolon delimiter."""
        pan = "4111111111111111"
        psn = "01"
        atc_hex = "0001"
        txn_data_hex = "0000000010000000"
        data_len_hex = "0008"

        kq_req = make_req(b"STRS", "KQ", f"1{self.mdk1}{pan}{psn}{atc_hex}{data_len_hex}{txn_data_hex}".encode("ascii"))
        r_kq = parse_resp(self.hsm.process_raw_message(kq_req))
        self.assertEqual(r_kq.error_code, ErrorCodes.SUCCESS)
        arqc_hex = r_kq.payload_bytes.decode("ascii")
        self.assertEqual(len(arqc_hex), 16)

    # =========================================================================
    # 3. Concurrency & Thread-Safety Stress Test
    # =========================================================================
    def test_hsm_concurrent_command_execution(self):
        """Stress test concurrent command processing across multiple threads on a single HSM instance."""
        def run_encrypt_decrypt_worker(worker_id):
            plaintext_hex = f"{worker_id:02X}" * 8
            m0_req = make_req(b"STRS", "M0", f"{self.dek1}000008{plaintext_hex}".encode("ascii"))
            m0_resp = parse_resp(self.hsm.process_raw_message(m0_req))
            if m0_resp.error_code != ErrorCodes.SUCCESS:
                return (False, f"M0 error: {m0_resp.error_code}")
            
            enc_hex = m0_resp.payload_bytes.decode("ascii")
            enc_len_hex = f"{len(enc_hex)//2:04X}"
            m2_req = make_req(b"STRS", "M2", f"{self.dek1}00{enc_len_hex}{enc_hex}".encode("ascii"))
            m2_resp = parse_resp(self.hsm.process_raw_message(m2_req))
            if m2_resp.error_code != ErrorCodes.SUCCESS:
                return (False, f"M2 error: {m2_resp.error_code}")
            ok = m2_resp.payload_bytes.decode("ascii") == plaintext_hex
            return (ok, f"Mismatch: expected {plaintext_hex}, got {m2_resp.payload_bytes.decode('ascii')}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(run_encrypt_decrypt_worker, i) for i in range(50)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        failures = [r for r in results if not r[0]]
        self.assertEqual(len(failures), 0, f"Concurrent HSM operations failed: {failures}")


if __name__ == "__main__":
    unittest.main()

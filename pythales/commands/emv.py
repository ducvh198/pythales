"""
EMV Processing Command Handlers:
- KQ/KR (Generate & Verify EMV ARQC / ARPC)
- KU/KV (EMV Secure Messaging Script Encryption/Decryption)
- KY/KZ (EMV Secure Messaging / Scripting)
"""

from binascii import hexlify, unhexlify
from typing import Tuple, Optional
import Crypto.Cipher.DES3

from pythales.commands.base import BaseCommandHandler
from pythales.commands.key_mgmt import _extract_key_string, _parse_key_payload
from pythales.commands.mac_data import iso9797_alg3_mac, pad_pkcs5, unpad_pkcs5, _get_key_raw, parse_payload_data_and_rem
from pythales.core.router import global_router
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.crypto.keyblock import TR31KeyBlock


def derive_emv_session_key(
    mdk: bytes,
    atc_bytes: bytes,
    pan: Optional[str] = None,
    psn: Optional[str] = None,
    option: str = "CSKD"
) -> bytes:
    """
    Derive EMV 3DES Session Key (SK_AC / SK_SMC / SK_SMI) from Master Key (MDK/IMK) and ATC.
    If pan and psn are provided, performs Card Unique Key (UDK) derivation first (EMV Option 1 CSKD):
      Z = bytes.fromhex((pan + psn)[-16:].rjust(16, "0"))
      Z_inv = bytes(b ^ 0xFF for b in Z)
      udk_left = 3DES_ECB(IMK, Z)
      udk_right = 3DES_ECB(IMK, Z_inv)
      udk = udk_left + udk_right
    Then derives session key using ATC:
      SK_left = 3DES_ECB(udk, ATC || F000000000)
      SK_right = 3DES_ECB(udk, ATC || 0F00000000)
    """
    if len(mdk) == 16:
        mdk = mdk + mdk[:8]

    base_key = mdk
    if pan is not None and psn is not None:
        pan_psn_str = (str(pan) + str(psn))[-16:].rjust(16, "0")
        try:
            z_left = unhexlify(pan_psn_str)
        except Exception:
            z_left = pan_psn_str.encode("ascii")[:8].rjust(8, b"\x00")
        z_right = bytes(b ^ 0xFF for b in z_left)

        cipher_imk = Crypto.Cipher.DES3.new(mdk, Crypto.Cipher.DES3.MODE_ECB)
        udk_left = cipher_imk.encrypt(z_left)
        udk_right = cipher_imk.encrypt(z_right)
        base_key = udk_left + udk_right
        if len(base_key) == 16:
            base_key = base_key + base_key[:8]

    if len(atc_bytes) < 2:
        atc_bytes = atc_bytes.rjust(2, b"\x00")
    else:
        atc_bytes = atc_bytes[:2]

    d_left = atc_bytes + b"\xF0\x00\x00\x00\x00\x00"
    d_right = atc_bytes + b"\x0F\x00\x00\x00\x00\x00"

    cipher_sk = Crypto.Cipher.DES3.new(base_key, Crypto.Cipher.DES3.MODE_ECB)
    sk_left = cipher_sk.encrypt(d_left)
    sk_right = cipher_sk.encrypt(d_right)
    return sk_left + sk_right


@global_router.register("KQ")
class KQHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        KQ Generate & Verify EMV ARQC / ARPC Handler.
        Modes:
        '0': Verify ARQC & Generate ARPC
        '1': Generate ARQC
        '2': Verify ARQC only
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 40:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "KQ payload too short")

        mode = payload_str[0]
        rem = payload_str[1:]

        mdk_str, rem = _extract_key_string(rem)
        mdk_raw = _get_key_raw(self.hsm, mdk_str, default_variant=9)

        # Parse PAN up to ';'
        if ";" in rem:
            pan, rem = rem.split(";", 1)
        else:
            pan = rem[:16]
            rem = rem[16:]

        psn = rem[:2]
        rem = rem[2:]

        atc_hex = rem[:4]
        rem = rem[4:]
        atc_bytes = unhexlify(atc_hex)

        data_len = int(rem[:4], 16)
        rem = rem[4:]

        has_arqc_suffix = mode in ("0", "2")
        txn_data_bytes, rem = parse_payload_data_and_rem(rem, data_len, has_suffix_16=has_arqc_suffix)

        # Derive Session Key SK_AC (including UDK derivation if pan and psn provided)
        sk_ac = derive_emv_session_key(mdk_raw, atc_bytes, pan=pan, psn=psn)

        # Compute ARQC (ISO 9797 Alg 3 MAC over transaction data)
        arqc_bytes = iso9797_alg3_mac(sk_ac, txn_data_bytes)
        computed_arqc_hex = hexlify(arqc_bytes).upper().decode("ascii")

        if mode == "1":
            # Mode 1: Generate ARQC
            return ErrorCodes.SUCCESS, computed_arqc_hex.encode("ascii")

        # Modes 0 and 2 require ARQC verification
        if len(rem) < 16:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "Missing ARQC to verify in KQ payload")

        arqc_to_verify = rem[:16].upper()
        rem = rem[16:]

        if computed_arqc_hex != arqc_to_verify:
            raise PayShieldException(ErrorCodes.PIN_VERIFICATION_FAILED, f"ARQC verification failed: computed '{computed_arqc_hex}' != '{arqc_to_verify}'")

        if mode == "2":
            # Mode 2: Verify ARQC only
            return ErrorCodes.SUCCESS, b""

        if mode == "0":
            # Mode 0: Verify ARQC and Generate ARPC
            arc_str = rem[:4] if len(rem) >= 4 else "3030"
            if len(arc_str) == 4 and all(c in "0123456789ABCDEFabcdef" for c in arc_str):
                arc_bytes = unhexlify(arc_str)
            else:
                arc_bytes = arc_str.encode("ascii")[:2]

            arc_padded = arc_bytes.ljust(8, b"\x00")
            arpc_in = bytes(a ^ b for a, b in zip(arqc_bytes, arc_padded))

            sk_ecb = sk_ac if len(sk_ac) == 24 else sk_ac + sk_ac[:8]
            cipher = Crypto.Cipher.DES3.new(sk_ecb, Crypto.Cipher.DES3.MODE_ECB)
            arpc_bytes = cipher.encrypt(arpc_in)
            arpc_hex = hexlify(arpc_bytes).upper()

            return ErrorCodes.SUCCESS, arpc_hex

        raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, f"Unsupported KQ mode '{mode}'")


@global_router.register("KU")
class KUHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        KU EMV Secure Messaging Script Encryption Handler.
        Payload: [MDK_SMC] + [ATC: 4 hex] + [DataLen: 4 hex] + [Script Data]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 41:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "KU payload too short")

        mdk_str, rem = _extract_key_string(payload_str)
        mdk_raw = _get_key_raw(self.hsm, mdk_str, default_variant=9)

        atc_hex = rem[:4]
        rem = rem[4:]
        atc_bytes = unhexlify(atc_hex)

        data_len = int(rem[:4], 16)
        rem = rem[4:]

        script_bytes, rem = parse_payload_data_and_rem(rem, data_len, has_suffix_16=False)

        sk_smc = derive_emv_session_key(mdk_raw, atc_bytes)
        if len(sk_smc) == 16:
            sk_smc = sk_smc + sk_smc[:8]

        padded_script = pad_pkcs5(script_bytes, 8)
        cipher = Crypto.Cipher.DES3.new(sk_smc, Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
        encrypted_script = cipher.encrypt(padded_script)

        return ErrorCodes.SUCCESS, hexlify(encrypted_script).upper()


@global_router.register("KV")
class KVHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        KV EMV Secure Messaging Script Decryption Handler.
        Payload: [MDK_SMC] + [ATC: 4 hex] + [DataLen: 4 hex] + [Encrypted Script Hex]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 41:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "KV payload too short")

        mdk_str, rem = _extract_key_string(payload_str)
        mdk_raw = _get_key_raw(self.hsm, mdk_str, default_variant=9)

        atc_hex = rem[:4]
        rem = rem[4:]
        atc_bytes = unhexlify(atc_hex)

        data_len = int(rem[:4], 16)
        rem = rem[4:]

        encrypted_script = unhexlify(rem[: data_len * 2])

        sk_smc = derive_emv_session_key(mdk_raw, atc_bytes)
        if len(sk_smc) == 16:
            sk_smc = sk_smc + sk_smc[:8]

        cipher = Crypto.Cipher.DES3.new(sk_smc, Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00" * 8)
        decrypted_padded = cipher.decrypt(encrypted_script)
        decrypted_script = unpad_pkcs5(decrypted_padded)

        return ErrorCodes.SUCCESS, hexlify(decrypted_script).upper()


@global_router.register("KY")
class KYHandler(BaseCommandHandler):
    def handle_payload(self, payload: bytes) -> Tuple[str, bytes]:
        """
        KY EMV Secure Messaging Scripting (Integrity/MAC) Handler.
        Payload: [MDK_SMI] + [ATC: 4 hex] + [DataLen: 4 hex] + [Script Data]
        """
        payload_str = payload.decode("ascii", errors="ignore")
        if len(payload_str) < 41:
            raise PayShieldException(ErrorCodes.INVALID_DATA_LENGTH, "KY payload too short")

        mdk_str, rem = _extract_key_string(payload_str)
        mdk_raw = _get_key_raw(self.hsm, mdk_str, default_variant=9)

        atc_hex = rem[:4]
        rem = rem[4:]
        atc_bytes = unhexlify(atc_hex)

        data_len = int(rem[:4], 16)
        rem = rem[4:]

        script_bytes, rem = parse_payload_data_and_rem(rem, data_len, has_suffix_16=False)

        sk_smi = derive_emv_session_key(mdk_raw, atc_bytes)
        mac_bytes = iso9797_alg3_mac(sk_smi, script_bytes)

        return ErrorCodes.SUCCESS, hexlify(mac_bytes).upper()


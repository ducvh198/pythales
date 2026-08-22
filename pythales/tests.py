#!/usr/bin/env python

import unittest
import struct

from pythales.hsm import HSM, PyThalesHSM, OutgoingMessage, DummyMessage, A0, BU, CA, CW, CY, DC, EC, HC, NC, NO, parse_message
from pythales.core.errors import ErrorCodes, PayShieldException
from pythales.core.frame import MessageFraming, CommandFrame, ResponseFrame
from pythales.core.router import CommandRouter, global_router
from pythales.crypto.lmk import LMKEngine
from pythales.crypto.keyblock import TR31Header, parse_header, TR31KeyBlock
from pythales.commands.key_mgmt import _parse_key_payload


class TestDummyMessage(unittest.TestCase):
    """
    """
    def setUp(self):
        self.message = DummyMessage(b'')

    def test_dummy_message_trace_empty(self):
        self.assertEqual(self.message.trace(), '')

    def test_dummy_message_get_non_existent_field(self):
        self.assertEqual(self.message.get('IDDQD'), None)

    def test_dummy_message_set(self):
        self.message.set('IDDQD', b'00')
        self.assertEqual(self.message.get('IDDQD'), b'00')

    def test_dummy_trace(self):
        self.message.set('IDDQD', b'00')
        self.assertEqual(self.message.trace(), '\t[IDDQD]: [00]\n')

class TestParseMessage(unittest.TestCase):
    """
    """
    def test_parse_message_none(self):
        self.assertEqual(parse_message(None), None)

    def test_get_length_incorrect(self):
        with self.assertRaisesRegex(ValueError, 'Expected message of length 6 but actual received message length is 2'):
            parse_message(b'\x00\x0600')

    def test_invalid_message_header(self):
        data = b'\x00\x06SSSS00'
        header = b'XDXD'
        with self.assertRaisesRegex(ValueError, 'Invalid header'):
            parse_message(data, header)

    def test_parse_message_command_code_and_data(self):
        parsed = parse_message(b'\x00\x07HDRDCXX', b'HDR')
        self.assertEqual(parsed[0], b'DC')
        self.assertEqual(parsed[1], b'XX')


class TestOutgoingMessageClass(unittest.TestCase):
    """
    """
    def test_outgoing_message(self):
        m = OutgoingMessage(header=b'XXXX')
        m.fields['Command Code'] = b'NG'
        m.fields['Response Code'] = b'00'
        m.fields['Data'] = b'7444321'
        self.assertEqual(m.build(), b'\x00\x0FXXXXNG007444321')


    def test_outgoing_message_no_header(self):
        m = OutgoingMessage(header=None)
        m.fields['Command Code'] = b'NG'
        m.fields['Response Code'] = b'00'
        m.fields['Data'] = b'7444321'
        self.assertEqual(m.build(), b'\x00\x0BNG007444321')


class TestMessageGet(unittest.TestCase):
    def setUp(self):
        self.m = OutgoingMessage(header=None)
        self.m.fields['Command Code'] = b'NG'
        self.m.fields['Response Code'] = b'00'
        self.m.fields['Data'] = b'7444321'

    def test_get_empty(self):
        self.assertEqual(self.m.get(''), None)

    def test_get_none(self):
        self.assertEqual(self.m.get(None), None)

    def test_get_command_code(self):
        self.assertEqual(self.m.get('Command Code'), b'NG')

class TestA0(unittest.TestCase):
    """
    DC command received:
    00 2f 53 53 53 53 41 30 31 37 30 44 55 3b 31 55         ./SSSSA0170DU;1U
    34 45 45 32 34 39 42 37 43 30 44 38 34 32 39 36         4EE249B7C0D84296
    30 37 32 38 44 46 31 42 32 45 43 38 37 30 31 45         0728DF1B2EC8701E
    58                                                      X
    """
    def setUp(self):
        data = b'170DU;1U4EE249B7C0D842960728DF1B2EC8701EX'
        self.a0 = A0(data)

    def test_mode_parsed(self):
        self.assertEqual(self.a0.fields['Mode'], b'1')

    def test_key_type_parsed(self):
        self.assertEqual(self.a0.fields['Key Type'], b'70D')

    def test_key_scheme_parsed(self):
        self.assertEqual(self.a0.fields['Key Scheme'], b'U')

    def test_zmk_tpk_flag_parsed(self):
        self.assertEqual(self.a0.fields['ZMK/TMK Flag'], b'1')

    def test_zmk_tpk_key_parsed(self):
        self.assertEqual(self.a0.fields['ZMK/TMK'], b'U4EE249B7C0D842960728DF1B2EC8701E')


class TestDC(unittest.TestCase):
    """
    DC command received:
    00 6a 53 53 53 53 44 43 55 44 45 41 44 42 45 45         .jSSSSDCUDEADBEE
    46 44 45 41 44 42 45 45 46 44 45 41 44 42 45 45         FDEADBEEFDEADBEE
    46 44 45 41 44 42 45 45 46 31 32 33 34 35 36 37         FDEADBEEF1234567
    38 39 30 41 42 43 44 45 46 31 32 33 34 35 36 37         890ABCDEF1234567
    38 39 30 41 42 43 44 45 46 32 42 36 38 37 41 45         890ABCDEF2B687AE
    46 43 33 34 42 31 41 38 39 30 31 30 30 31 31 32         FC34B1A890100112
    33 34 35 36 37 38 39 31 38 37 32 33                     345678918723
    """
    def setUp(self):
        data = b'UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A890100112345678918723'
        self.dc = DC(data)

    def test_tpk_parsed(self):
        self.assertEqual(self.dc.fields['TPK'], b'UDEADBEEFDEADBEEFDEADBEEFDEADBEEF')

    def test_pvk_parsed(self):
        self.assertEqual(self.dc.fields['PVK Pair'], b'1234567890ABCDEF1234567890ABCDEF')

    def test_pinblock_parsed(self):
        self.assertEqual(self.dc.fields['PIN block'], b'2B687AEFC34B1A89')

    def test_pinblock_format_code_parsed(self):
        self.assertEqual(self.dc.fields['PIN block format code'], b'01')

    def test_account_number_parsed(self):
        self.assertEqual(self.dc.fields['Account Number'], b'001123456789')

    def test_pvki_parsed(self):
        self.assertEqual(self.dc.fields['PVKI'], b'1')

    def test_pvv_parsed(self):
        self.assertEqual(self.dc.fields['PVV'], b'8723')

    def test_DC_desciprion(self):
        self.assertEqual(self.dc.description, 'Verify PIN')


class TestCA(unittest.TestCase):
    """
    18:47:19.371109 << 108 bytes received from 192.168.56.101:33284:
        00 6a 53 53 53 53 43 41 55 45 44 34 41 33 35 44         .jSSSSCAUED4A35D
        35 32 43 39 30 36 33 41 31 45 44 34 41 33 35 44         52C9063A1ED4A35D
        35 32 43 39 30 36 33 41 31 55 44 33 39 44 33 39         52C9063A1UD39D39
        45 42 37 43 39 33 32 43 46 33 36 37 43 39 37 43         EB7C932CF367C97C
        35 42 31 30 42 32 43 31 39 35 31 32 37 44 46 33         5B10B2C195127DF3
        36 36 42 38 36 41 45 32 44 39 41 37 30 31 30 33         66B86AE2D9A70103
        35 35 32 30 30 30 30 30 30 30 31 32                     552000000012
    """
    def setUp(self):
        data = b'UED4A35D52C9063A1ED4A35D52C9063A1UD39D39EB7C932CF367C97C5B10B2C195127DF366B86AE2D9A70103552000000012'
        self.ca = CA(data)

    def test_tpk_parsed(self):
        self.assertEqual(self.ca.fields['TPK'], b'UED4A35D52C9063A1ED4A35D52C9063A1')

    def test_dest_key_parsed(self):
        self.assertEqual(self.ca.fields['Destination Key'], b'UD39D39EB7C932CF367C97C5B10B2C195')

    def test_max_pin_length_parsed(self):
        self.assertEqual(self.ca.fields['Maximum PIN Length'], b'12')

    def test_source_pin_block_parsed(self):
        self.assertEqual(self.ca.fields['Source PIN block'], b'7DF366B86AE2D9A7')

    def test_source_pin_block_format_parsed(self):
        self.assertEqual(self.ca.fields['Source PIN block format'], b'01')

    def test_dest_pin_block_format_parsed(self):
        self.assertEqual(self.ca.fields['Destination PIN block format'], b'03')

    def test_account_number_parsed(self):
        self.assertEqual(self.ca.fields['Account Number'], b'552000000012')


class TestCW(unittest.TestCase):
    """
    00 3f 53 53 53 53 43 57 55 31 43 31 45 42 31 30         .?SSSSCWU1C1EB10
    39 30 36 38 31 43 43 39 45 36 30 30 33 45 30 35         90681CC9E6003E05
    32 31 37 43 37 30 37 37 45 34 35 37 35 32 37 32         217C7077E4575272
    32 32 32 35 36 37 31 32 32 3b 32 30 31 30 30 30         222567122;201000
    30                                                      0
    """
    def setUp(self):
        data = b'U1C1EB1090681CC9E6003E05217C7077E4575272222567122;2010000'
        self.cy = CW(data)

    def test_cvk_parsed(self):
        self.assertEqual(self.cy.fields['CVK'], b'U1C1EB1090681CC9E6003E05217C7077E')

    def test_account_number_parsed(self):
        self.assertEqual(self.cy.fields['Primary Account Number'], b'4575272222567122')

    def test_expiry_date_parsed(self):
        self.assertEqual(self.cy.fields['Expiration Date'], b'2010')

    def test_service_code_parsed(self):
        self.assertEqual(self.cy.fields['Service Code'], b'000')


class TestCY(unittest.TestCase):
    """
    00 42 53 53 53 53 43 59 55 34 34 39 44 46 31 36         .BSSSSCYU449DF16
    37 39 46 34 41 34 45 30 36 39 35 45 39 39 44 39         79F4A4E0695E99D9
    32 31 41 32 35 33 44 43 42 30 30 30 38 39 39 30         21A253DCB0008990
    30 31 31 32 33 34 35 36 37 38 39 30 3b 31 38 30         011234567890;180
    39 32 30 31                                             9201

    """
    def setUp(self):
        data = b'U449DF1679F4A4E0695E99D921A253DCB0008990011234567890;1809201'
        self.cy = CY(data)

    def test_cvk_parsed(self):
        self.assertEqual(self.cy.fields['CVK'], b'U449DF1679F4A4E0695E99D921A253DCB')

    def test_cvv_parsed(self):
        self.assertEqual(self.cy.fields['CVV'], b'000')

    def test_account_number_parsed(self):
        self.assertEqual(self.cy.fields['Primary Account Number'], b'8990011234567890')

    def test_expiry_date_parsed(self):
        self.assertEqual(self.cy.fields['Expiration Date'], b'1809')

    def test_service_code_parsed(self):
        self.assertEqual(self.cy.fields['Service Code'], b'201')

class TestECAccountNumber(unittest.TestCase):
    """
    00 6a 53 53 53 53 45 43 55 41 45 37 39 44 32 30         .jSSSSECUAE79D20
    33 46 39 36 34 30 41 39 33 43 46 42 41 31 35 35         3F9640A93CFBA155
    45 33 34 35 39 35 33 46 36 37 33 33 36 44 35 30         E345953F67336D50
    43 34 37 31 32 38 44 37 31 30 44 46 34 35 30 42         C47128D710DF450B
    43 42 32 43 36 34 36 31 42 43 33 32 46 31 30 34         CB2C6461BC32F104
    41 36 38 34 36 42 44 38 37 30 31 34 30 37 30 30         A6846BD870140700
    30 30 30 30 30 31 30 31 32 33 34 35                     000001012345

    """
    def setUp(self):
        data = b'UAE79D203F9640A93CFBA155E345953F67336D50C47128D710DF450BCB2C6461BC32F104A6846BD870140700000001012345'
        self.ec = EC(data)

    def test_zpk_parsed(self):
        self.assertEqual(self.ec.fields['ZPK'], b'UAE79D203F9640A93CFBA155E345953F6')

    def test_pvk_pair_parsed(self):
        self.assertEqual(self.ec.fields['PVK Pair'], b'7336D50C47128D710DF450BCB2C6461B')

    def test_pin_block_parsed(self):
        self.assertEqual(self.ec.fields['PIN block'], b'C32F104A6846BD87')

    def test_pin_block_format_code_parsed(self):
        self.assertEqual(self.ec.fields['PIN block format code'], b'01')

    def test_pan_parsed(self):
        self.assertEqual(self.ec.fields['Account Number'], b'407000000010')

    def test_pvki_parsed(self):
        self.assertEqual(self.ec.fields['PVKI'], b'1')

    def test_pvv_parsed(self):
        self.assertEqual(self.ec.fields['PVV'], b'2345')

class TestECToken(unittest.TestCase):
    """
    """
    def setUp(self):
        data = b'UAE79D203F9640A93CFBA155E345953F67336D50C47128D710DF450BCB2C6461BC32F104A6846BD8704xxxxxxxxxxxxzzzzzz12345'
        self.ec = EC(data)

    def test_zpk_parsed(self):
        self.assertEqual(self.ec.fields['ZPK'], b'UAE79D203F9640A93CFBA155E345953F6')

    def test_pvk_pair_parsed(self):
        self.assertEqual(self.ec.fields['PVK Pair'], b'7336D50C47128D710DF450BCB2C6461B')

    def test_pin_block_parsed(self):
        self.assertEqual(self.ec.fields['PIN block'], b'C32F104A6846BD87')

    def test_pin_block_format_code_parsed(self):
        self.assertEqual(self.ec.fields['PIN block format code'], b'04')

    def test_pan_parsed(self):
        self.assertEqual(self.ec.fields['Token'], b'xxxxxxxxxxxxzzzzzz')

    def test_pvki_parsed(self):
        self.assertEqual(self.ec.fields['PVKI'], b'1')

    def test_pvv_parsed(self):
        self.assertEqual(self.ec.fields['PVV'], b'2345')


class TestHC(unittest.TestCase):
    """
    16:48:04.000521 << 45 bytes received from 192.168.56.101:42292:
    00 2b 53 53 53 53 48 43 55 31 32 33 34 35 36 37         .+SSSSHCU1234567
    38 39 30 41 42 43 44 45 46 31 32 33 34 35 36 37         890ABCDEF1234567
    38 39 30 41 42 43 44 45 46 3b 58 55 31                  890ABCDEF;XU1

    """
    def setUp(self):
        data = b'U1234567890ABCDEF1234567890ABCDEF;XU1'
        self.hc = HC(data)

    def test_current_key_parsed(self):
        self.assertEqual(self.hc.fields['Current Key'], b'U1234567890ABCDEF1234567890ABCDEF')


class TestBU(unittest.TestCase):
    """
    16:53:16.560494 << 44 bytes received from 192.168.56.101:42364:
    00 2a 53 53 53 53 42 55 30 32 31 55 41 39 37 38         .*SSSSBU021UA978
    33 31 38 36 32 45 33 31 43 43 43 33 36 45 38 35         31862E31CCC36E85
    34 46 45 31 38 34 45 45 36 34 35 33                     4FE184EE6453
    """
    def setUp(self):
        data = b'021UA97831862E31CCC36E854FE184EE6453'
        self.bu = BU(data)

    def test_key_type_code_parsed(self):
        self.assertEqual(self.bu.fields['Key Type Code'], b'02')

    def test_key_length_flag_parsed(self):
        self.assertEqual(self.bu.fields['Key Length Flag'], b'1')

    def test_key_parsed(self):
        self.assertEqual(self.bu.fields['Key'], b'UA97831862E31CCC36E854FE184EE6453')



class TestHSMThread(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header='SSSS', skip_parity=True)

    def test_decrypt_pinblock(self):
        self.assertEqual(self.hsm._decrypt_pinblock(b'2B687AEFC34B1A89', b'UDEADBEEFDEADBEEFDEADBEEFDEADBEEF'), b'2AD242FBD61291DB')

    """
    hsm.translate_pinblock()
    """
    def test_translate_pinblock_different_pinblock_formats(self):
        data = b'UED4A35D52C9063A1ED4A35D52C9063A1UD39D39EB7C932CF367C97C5B10B2C195127DF366B86AE2D9A70103552000000012'
        self.ca = CA(data)
        with self.assertRaisesRegex(ValueError, 'Cannot translate PIN block from format 01 to format 03'):
            self.hsm.translate_pinblock(self.ca)

    def test_translate_pinblock_unsupported_format(self):
        data = b'UED4A35D52C9063A1ED4A35D52C9063A1UD39D39EB7C932CF367C97C5B10B2C195127DF366B86AE2D9A70303552000000012'
        self.ca = CA(data)
        with self.assertRaisesRegex(ValueError, 'Unsupported PIN block format: 03'):
            self.hsm.translate_pinblock(self.ca)

    """
    User-defined key
    """
    def test_user_defined_key_wrong_key_size(self):
        with self.assertRaises(ValueError):
            self.hsm = HSM(key='DEADBEAF')

    def test_user_defined_key_value(self):
        with self.assertRaises(ValueError):
            self.hsm = HSM(key='iddqdeef deadbeef deadbeef deadbeef')

    """
    verify_pin()
    """
    def test_verify_pin_EC(self):
        """
        00 6a 53 53 53 53 45 43 55 38 32 37 45 36 37 42         .jSSSSECU827E67B
        35 39 41 31 44 36 42 38 46 38 32 37 45 36 37 42         59A1D6B8F827E67B
        35 39 41 31 44 36 42 38 46 37 33 33 36 44 35 30         59A1D6B8F7336D50
        43 34 37 31 32 38 44 37 31 30 44 46 34 35 30 42         C47128D710DF450B
        43 42 32 43 36 34 36 31 42 43 33 32 46 31 30 34         CB2C6461BC32F104
        41 36 38 34 36 42 44 38 37 30 31 34 30 37 30 30         A6846BD870140700
        30 30 30 30 30 31 30 31 33 38 34 33                     000001013843

        [ZPK                  ]: [U827E67B59A1D6B8F827E67B59A1D6B8F]
        [PVK Pair             ]: [7336D50C47128D710DF450BCB2C6461B]
        [PIN block            ]: [C32F104A6846BD87]
        [PIN block format code]: [01]
        [Account Number       ]: [407000000010]
        [PVKI                 ]: [1]
        [PVV                  ]: [3843]
        """
        data = b'U827E67B59A1D6B8F827E67B59A1D6B8F7336D50C47128D710DF450BCB2C6461BC32F104A6846BD870140700000001013843'
        request = EC(data)
        response = self.hsm.verify_pin(request)
        self.assertEqual(response.get('Response Code'), b'ED')
        self.assertEqual(response.get('Error Code'), b'00')


    def test_verify_pin_DC(self):
        """
        """
        data = b'U827E67B59A1D6B8F827E67B59A1D6B8F7336D50C47128D710DF450BCB2C6461BC32F104A6846BD870140700000001013843'
        request = DC(data)
        response = self.hsm.verify_pin(request)
        self.assertEqual(response.get('Response Code'), b'DD')
        self.assertEqual(response.get('Error Code'), b'00')

    """
    verify_cvv()
    """
    def test_verify_cvv_proper_response_code(self):
        """
        00 42 53 53 53 53 43 59 55 31 43 31 45 42 31 30         .BSSSSCYU1C1EB10
        39 30 36 38 31 43 43 39 45 36 30 30 33 45 30 35         90681CC9E6003E05
        32 31 37 43 37 30 37 37 45 36 34 30 34 31 37 34         217C7077E6404174
        30 37 30 30 30 30 30 30 30 31 30 34 3b 31 37 31         070000000104;171
        32 32 30 31                                             2201
        """
        data = b'U1C1EB1090681CC9E6003E05217C7077E6404174070000000104;1712201'
        request = CY(data)
        response = self.hsm.verify_cvv(request)
        self.assertEqual(response.get('Response Code'), b'CZ')

        """
    generate_cvv()
    """
    def test_generate_cvv_proper_response_code(self):
        """
        00 3f 53 53 53 53 43 57 55 31 43 31 45 42 31 30         .?SSSSCWU1C1EB10
        39 30 36 38 31 43 43 39 45 36 30 30 33 45 30 35         90681CC9E6003E05
        32 31 37 43 37 30 37 37 45 34 35 37 35 32 37 32         217C7077E4575272
        32 32 32 35 36 37 31 32 32 3b 32 30 31 30 30 30         222567122;201000
        30                                                      0
        """
        data = b'U1C1EB1090681CC9E6003E05217C7077E4575272222567122;2010000'
        request = CW(data)
        response = self.hsm.generate_cvv(request)
        self.assertEqual(response.get('Response Code'), b'CX')
        self.assertEqual(response.get('Error Code'), b'00')
        self.assertEqual(response.get('CVV'), b'670')

    """
    generate_key()
    """
    def test_generate_key_proper_response_code(self):
        """
        """
        data = b'U1234567890ABCDEF1234567890ABCDEF;XU1'
        request = HC(data)
        response = self.hsm.generate_key(request)
        self.assertEqual(response.get('Response Code'), b'HD')
        self.assertEqual(response.get('Error Code'), b'00')

    """
    generate_key_a0()
    """
    def test_generate_key_a0_proper_response_code(self):
        """
        """
        data = b'0002U'
        request = A0(data)
        response = self.hsm.generate_key_a0(request)
        self.assertEqual(response.get('Response Code'), b'A1')
        self.assertEqual(response.get('Error Code'), b'00')

    def test_generate_key_a0_with_zmk_proper_response_code(self):
        """
        """
        data = b'170DU;1U4EE249B7C0D842960728DF1B2EC8701EX'
        request = A0(data)
        response = self.hsm.generate_key_a0(request)
        self.assertEqual(response.get('Response Code'), b'A1')
        self.assertEqual(response.get('Error Code'), b'00')
        self.assertEqual(response.get('Key under ZMK')[0], 85) # b'U'
        self.assertEqual(len(response.get('Key under ZMK')), 33)
        self.assertEqual(len(response.get('Key Check Value')), 6)


class TestHSMResponsesMapping(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header='SSSS', skip_parity=True)

    def test_ZZ_response(self):
        response = self.hsm.get_response(DummyMessage(b''))
        self.assertEqual(response.get('Response Code'), b'ZZ')

    def test_BU_response(self):
        data = b'021UA97831862E31CCC36E854FE184EE6453'
        response = self.hsm.get_response(BU(data))
        self.assertEqual(response.get('Response Code'), b'BV')


    def test_DC_response(self):
        data = b'UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A890100112345678918723'
        response = self.hsm.get_response(DC(data))
        self.assertEqual(response.get('Response Code'), b'DD')


    def test_CA_response(self):
        data = b'UED4A35D52C9063A1ED4A35D52C9063A1UD39D39EB7C932CF367C97C5B10B2C195127DF366B86AE2D9A70101552000000012'
        response = self.hsm.get_response(CA(data))
        self.assertEqual(response.get('Response Code'), b'CB')

    def test_CY_response(self):
        data = b'U449DF1679F4A4E0695E99D921A253DCB0008990011234567890;1809201'
        response = self.hsm.get_response(CY(data))
        self.assertEqual(response.get('Response Code'), b'CZ')


    def test_HC_response(self):
        data = b'U1234567890ABCDEF1234567890ABCDEF;XU1'
        response = self.hsm.get_response(HC(data))
        self.assertEqual(response.get('Response Code'), b'HD')


    def test_NC_response(self):
        response = self.hsm.get_response(NC(b''))
        self.assertEqual(response.get('Response Code'), b'ND')
        self.assertEqual(response.get('Error Code'), b'00')

    def test_NO_response(self):
        response = self.hsm.get_response(NO(b'00'))
        self.assertEqual(response.get('Response Code'), b'NP')
        self.assertEqual(response.get('Error Code'), b'00')
        self.assertEqual(response.get('Data'), b'00')


class TestPriorityCommands(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM()

    def test_package_export(self):
        from pythales import HSM as ExportedHSM
        hsm_inst = ExportedHSM()
        self.assertIsNotNone(hsm_inst)

    def test_network_echo_no(self):
        request_raw = b"\x00\x0CNOECHO_TEST!"
        response_raw = self.hsm.process_raw_message(request_raw)
        # Expect response starting with NP + 00 + ECHO_TEST!
        self.assertTrue(response_raw.startswith(b"NP00ECHO_TEST!"))

    def test_generate_key_a0(self):
        # Mode 0 (under LMK), KeyType 001 (ZPK), Scheme U
        request_raw = b"A00001U"
        response_raw = self.hsm.process_raw_message(request_raw)
        self.assertTrue(response_raw.startswith(b"A100"))
        # Payload format: A1 (2) + 00 (2) + 'U' + 32-hex-key + 6-hex-kcv = 43 chars
        self.assertEqual(len(response_raw), 4 + 1 + 32 + 6)

    def test_cvv_workflow_cw_cy(self):
        # A0 Generate CVK (KeyType 003)
        gen_cw_key = self.hsm.process_raw_message(b"A00003U")
        cvk_hex = gen_cw_key[4:4+33].decode("ascii")

        # CW Generate CVV
        # CW + CVK (33) + PAN (16) + Exp (4) + ServiceCode (3)
        cw_req = f"CW{cvk_hex}41111111111111112512101".encode("ascii")
        cw_resp = self.hsm.process_raw_message(cw_req)
        self.assertTrue(cw_resp.startswith(b"CX00"))
        generated_cvv = cw_resp[4:].decode("ascii")
        self.assertEqual(len(generated_cvv), 3)

        # CY Verify CVV (valid)
        cy_req = f"CY{cvk_hex}{generated_cvv}41111111111111112512101".encode("ascii")
        cy_resp = self.hsm.process_raw_message(cy_req)
        self.assertEqual(cy_resp, b"CZ00")

        # CY Verify CVV (invalid CVV)
        cy_bad_req = f"CY{cvk_hex}999411111111111111112512101".encode("ascii")
        cy_bad_resp = self.hsm.process_raw_message(cy_bad_req)
        self.assertEqual(cy_bad_resp[:4], b"CZ01")






    def test_data_encryption_m0_m2(self):
        # Generate DEK (KeyType 008)
        gen_dek = self.hsm.process_raw_message(b"A00008U")
        dek_hex = gen_dek[4:4+33].decode("ascii")

        # M0 Encrypt Data (ECB mode '0')
        # Plaintext "PAYSHIELD123456" -> 15 bytes -> hex len 000F
        plaintext_hex = "504159534849454C44313233343536"
        m0_req = f"M0{dek_hex}0000F{plaintext_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"M100"))
        encrypted_hex = m0_resp[4:].decode("ascii")

        # M2 Decrypt Data
        enc_bytes_len = len(encrypted_hex) // 2
        len_hex = f"{enc_bytes_len:04X}"
        m2_req = f"M2{dek_hex}0{len_hex}{encrypted_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"M300"))
        decrypted_hex = m2_resp[4:].decode("ascii")
        self.assertEqual(decrypted_hex, plaintext_hex)


class TestMilestoneM1CoreAndLMK(unittest.TestCase):
    def test_package_export(self):
        from pythales import HSM as PackageExportHSM
        hsm = PackageExportHSM()
        self.assertIsNotNone(hsm)

    def test_error_codes_completeness_and_exception(self):
        expected_codes = (
            '00', '01', '02', '03', '04', '05', '10', '11', '12', '13',
            '15', '17', '21', '23', '26', '27', '28', '29', '68', '80',
            '83', 'A6', 'A7', 'A8', 'BC'
        )
        for code in expected_codes:
            self.assertIn(code, ErrorCodes.ALL_CODES)
            self.assertIn(code, ErrorCodes.MESSAGES)
            msg = ErrorCodes.get_message(code)
            self.assertFalse(msg.startswith("Unknown"))

        exc = PayShieldException("10")
        self.assertEqual(exc.error_code, "10")
        self.assertIn("Source key parity error", exc.message)

        exc_custom = PayShieldException("01", "Custom LMK Failure")
        self.assertEqual(exc_custom.error_code, "01")
        self.assertEqual(exc_custom.message, "Custom LMK Failure")

    def test_tcp_envelope_framing_parser(self):
        raw_msg = b"\x00\x08HDRNC123"
        frame = MessageFraming.parse_request(raw_msg, header_length=3)
        self.assertEqual(frame.header_bytes, b"HDR")
        self.assertEqual(frame.command_code, "NC")
        self.assertEqual(frame.payload_bytes, b"123")
        self.assertFalse(frame.delimiter_present)
        self.assertEqual(frame.trailer_bytes, b"")

        raw_delim_msg = b"HDRNC123\x19TRAILER_DATA"
        frame_delim = MessageFraming.parse_request(raw_delim_msg, header_length=3)
        self.assertEqual(frame_delim.header_bytes, b"HDR")
        self.assertEqual(frame_delim.command_code, "NC")
        self.assertEqual(frame_delim.payload_bytes, b"123")
        self.assertTrue(frame_delim.delimiter_present)
        self.assertEqual(frame_delim.trailer_bytes, b"TRAILER_DATA")

    def test_error_code_truncation_rule(self):
        succ_resp = MessageFraming.format_response(b"HDR", "ND", "00", b"DATA_FIELDS")
        self.assertEqual(succ_resp, b"HDRND00DATA_FIELDS")

        err_resp = MessageFraming.format_response(b"HDR", "ND", "01", b"COMMAND_DIAGNOSTIC")
        self.assertEqual(err_resp, b"HDRND01COMMAND_DIAGNOSTIC")

        err_prefix = MessageFraming.format_response(b"HDR", "ND", "15", b"INVALID_LEN", include_length_prefix=True)
        self.assertEqual(err_prefix, b"\x00\x12HDRND15INVALID_LEN")

        resp_frame = ResponseFrame(header_bytes=b"HDR", response_code="ND", error_code="A7", payload_bytes=b"SECRET")
        self.assertEqual(resp_frame.build(), b"HDRNDA7SECRET")

    def test_command_router_registration_and_dispatch(self):
        test_router = CommandRouter()

        @test_router.register("TZ")
        class TestHandler:
            def __init__(self, ctx=None):
                self.ctx = ctx

            def handle(self, frame=None):
                return b"TZ00" + (frame.payload_bytes if frame else b"")

        handler_cls = test_router.dispatch("TZ")
        self.assertEqual(handler_cls, TestHandler)

        cmd_frame = CommandFrame(header_bytes=b"", command_code="TZ", payload_bytes=b"OK", raw_body=b"TZOK")
        result = test_router.dispatch("TZ", None, cmd_frame)
        self.assertEqual(result, b"TZ00OK")

        with self.assertRaises(PayShieldException) as cm:
            test_router.dispatch("XX")
        self.assertEqual(cm.exception.error_code, ErrorCodes.FUNCTION_NOT_SUPPORTED)

    def test_lmk_variant_xor_engine(self):
        base_lmk_16 = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
        lmk_eng = LMKEngine(base_lmk_16)

        var0 = lmk_eng.get_variant_lmk(0)
        self.assertEqual(var0, base_lmk_16)

        var1 = lmk_eng.get_variant_lmk(1)
        expected_var1 = (
            bytes([base_lmk_16[0] ^ 1]) + base_lmk_16[1:8] +
            bytes([base_lmk_16[8] ^ 1]) + base_lmk_16[9:16]
        )
        self.assertEqual(var1, expected_var1)

        var7 = lmk_eng.get_variant_lmk(7)
        expected_var7 = (
            bytes([base_lmk_16[0] ^ 7]) + base_lmk_16[1:8] +
            bytes([base_lmk_16[8] ^ 7]) + base_lmk_16[9:16]
        )
        self.assertEqual(var7, expected_var7)

        var8 = lmk_eng.get_variant_lmk(8)
        expected_var8 = (
            bytes([base_lmk_16[0] ^ 8]) + base_lmk_16[1:8] +
            bytes([base_lmk_16[8] ^ 8]) + base_lmk_16[9:16]
        )
        self.assertEqual(var8, expected_var8)

        clear_key = b"\x11" * 16
        for v in range(10):
            enc = lmk_eng.encrypt_under_lmk(clear_key, variant=v)
            dec = lmk_eng.decrypt_under_lmk(enc, variant=v)
            self.assertEqual(dec, clear_key)

        with self.assertRaises(PayShieldException) as cm:
            lmk_eng.get_variant_lmk(12)
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_KEY_SCHEME)

    def test_legacy_pci_policy_hook_does_not_redefine_a7(self):
        lmk_eng = LMKEngine(b"\x00" * 16, pci_mode=True)
        self.assertTrue(lmk_eng.validate_pci_key_separation("002", variant=2))
        self.assertTrue(lmk_eng.validate_pci_key_separation("002", variant=7))
        self.assertEqual(ErrorCodes.INVALID_ALGORITHM, "A7")

    def test_legacy_dek_policy_hook_does_not_redefine_a8(self):
        lmk_eng = LMKEngine(b"\x00" * 16)
        self.assertTrue(lmk_eng.validate_dek_protection("008", variant=2, export_scheme="U"))
        self.assertEqual(ErrorCodes.INVALID_MODE_OF_USE, "A8")


class TestMilestoneM2KeyMgmtAndKeyBlock(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="SSSS", skip_parity=True)

    def test_tr31_header_parsing(self):
        hdr_str = "S004821TB00N0000"
        hdr = parse_header(hdr_str)
        self.assertEqual(hdr.version_id, "S")
        self.assertEqual(hdr.key_length, 48)
        self.assertEqual(hdr.key_usage, "21")
        self.assertEqual(hdr.algorithm, "T")
        self.assertEqual(hdr.mode_of_use, "B")
        self.assertEqual(hdr.key_version, "00")
        self.assertEqual(hdr.exportability, "N")

        with self.assertRaises(PayShieldException) as cm:
            parse_header("SHORT_HEADER")
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_KEY_BLOCK)

    def test_tr31_key_block_wrap_and_unwrap(self):
        kbmk = b"\x01" * 16
        key_bytes = b"\xAA" * 16
        hdr = TR31Header("S", 48, "21", "T", "B", "00", "E")

        wrapped = TR31KeyBlock.wrap(key_bytes, hdr, kbmk)
        self.assertTrue(wrapped.startswith(b"S008021TB00E0000"))

        unwrapped_hdr, unwrapped_key = TR31KeyBlock.unwrap(wrapped, kbmk)
        self.assertEqual(unwrapped_key, key_bytes)
        self.assertEqual(unwrapped_hdr.key_usage, "21")

        # Test MAC verification failure
        corrupted = wrapped[:-4] + b"XXXX"
        with self.assertRaises(PayShieldException) as cm:
            TR31KeyBlock.unwrap(corrupted, kbmk)
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_KEY_CHECK_VALUE)

    def test_nc_nd_and_no_np_commands(self):
        # NC Diagnostics
        nc_req = b"\x00\x06SSSSNC"
        nc_resp = self.hsm.process_raw_message(nc_req)
        self.assertTrue(nc_resp.startswith(b"SSSSND00"))
        # 4 (header) + 2 (ND) + 2 (00) + 16 (LMK KCV) + 9 (firmware) = 33
        self.assertEqual(len(nc_resp), 33)

        # NO Network Echo
        no_req = b"\x00\x0DSSSSNOECHO123"
        no_resp = self.hsm.process_raw_message(no_req)
        self.assertEqual(no_resp, b"SSSSNP00ECHO123")

    def test_a0_key_generation_all_schemes_and_types(self):
        key_schemes = ["U", "T", "S", "X", "Y"]
        key_types = ["000", "001", "002", "003", "005", "00A", "00B", "402"]

        for kt in key_types:
            for ks in key_schemes:
                req = f"SSSSA00{kt}{ks}".encode("ascii")
                resp = self.hsm.process_raw_message(req)
                self.assertTrue(resp.startswith(b"SSSSA100"), f"Failed for type {kt}, scheme {ks}")

                payload = resp[8:]  # strip SSSSA100
                if ks == "S":
                    self.assertTrue(payload.startswith(b"S"))
                else:
                    expected_hex_len = 48 if ks in ("T", "Y") else 32
                    self.assertEqual(payload[0:1], ks.encode("ascii"))
                    self.assertEqual(len(payload), 1 + expected_hex_len + 6)

    def test_a0_mode_1_with_zmk(self):
        # Generate ZMK under LMK first
        zmk_resp = self.hsm.process_raw_message(b"SSSSA00000U")
        zmk_hex = zmk_resp[8:8+33].decode("ascii")

        # Mode 1 generate ZPK under LMK and ZMK
        a0_m1_req = f"SSSSA01001U;1{zmk_hex}".encode("ascii")
        a0_m1_resp = self.hsm.process_raw_message(a0_m1_req)
        self.assertTrue(a0_m1_resp.startswith(b"SSSSA100"))
        # SSSSA100 (8) + KeyLMK (33) + KeyZMK (33) + KCV (6) = 80
        self.assertEqual(len(a0_m1_resp), 80)

    def test_bu_kcv_generation(self):
        # Generate key under LMK
        gen_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        key_lmk = gen_resp[8:8+33].decode("ascii")
        expected_kcv = gen_resp[-6:].decode("ascii")

        bu_req = f"SSSSBU001{key_lmk}".encode("ascii")
        bu_resp = self.hsm.process_raw_message(bu_req)
        self.assertEqual(bu_resp, f"SSSSBV00{expected_kcv}".encode("ascii"))

    def test_a2_a4_component_generation_and_forming(self):
        # A2 Generate 2 components
        a2_req = b"SSSSA20001U"
        a2_resp = self.hsm.process_raw_message(a2_req)
        self.assertTrue(a2_resp.startswith(b"SSSSA300"))

        payload = a2_resp[8:].decode("ascii")
        key_lmk = payload[:33]
        kcv = payload[33:39]
        comp1 = payload[39:72]
        comp2 = payload[72:105]

        # A4 Form key back from components
        a4_req = f"SSSSA42001U{comp1}{comp2}".encode("ascii")
        a4_resp = self.hsm.process_raw_message(a4_req)
        self.assertTrue(a4_resp.startswith(b"SSSSA500"))

        formed_payload = a4_resp[8:].decode("ascii")
        formed_key_lmk = formed_payload[:33]
        formed_kcv = formed_payload[33:39]

        self.assertEqual(formed_key_lmk, key_lmk)
        self.assertEqual(formed_kcv, kcv)

    def test_a6_import_zmk_and_dek_protection_rule(self):
        # Generate ZMK under LMK
        zmk_resp = self.hsm.process_raw_message(b"SSSSA00000U")
        zmk_hex = zmk_resp[8:8+33].decode("ascii")

        # Generate ZPK under ZMK (mode 1)
        zpk_m1_resp = self.hsm.process_raw_message(f"SSSSA01001U;1{zmk_hex}".encode("ascii"))
        zpk_under_zmk = zpk_m1_resp[8+33:8+33+33].decode("ascii")

        # A6 Import ZPK under ZMK
        a6_req = f"SSSSA6001{zmk_hex}{zpk_under_zmk}U".encode("ascii")
        a6_resp = self.hsm.process_raw_message(a6_req)
        self.assertTrue(a6_resp.startswith(b"SSSSA700"))

        # Variant LMK permits DEK import in variant format.
        dek_under_zmk = zpk_under_zmk  # scheme U
        a6_dek_bad = f"SSSSA600B{zmk_hex}{dek_under_zmk}U".encode("ascii")
        a6_dek_resp = self.hsm.process_raw_message(a6_dek_bad)
        self.assertTrue(a6_dek_resp.startswith(b"SSSSA700"))

        # DEK imported as TR-31 Key Block ('S') succeeds
        # Generate DEK as TR-31 Key Block wrapped under ZMK (using KW command)
        hdr = "S004821TB00E0000"
        kw_dek_resp = self.hsm.process_raw_message(f"SSSSKW00B{zmk_hex}{hdr}".encode("ascii"))
        dek_block_zmk = kw_dek_resp[8+33:-6].decode("ascii")

        a6_dek_good = f"SSSSA600B{zmk_hex}{dek_block_zmk}S".encode("ascii")
        a6_dek_good_resp = self.hsm.process_raw_message(a6_dek_good)
        self.assertTrue(a6_dek_good_resp.startswith(b"SSSSA700"))

    def test_gi_scheme_translation(self):
        # Generate key scheme U
        gen_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        key_u = gen_resp[8:8+33].decode("ascii")

        # Translate U -> S (TR-31)
        gi_req = f"SSSSGI001US{key_u}".encode("ascii")
        gi_resp = self.hsm.process_raw_message(gi_req)
        self.assertTrue(gi_resp.startswith(b"SSSSGJ00"))
        self.assertIn(b"S008021TB00E0000", gi_resp)

        # Translate S -> U
        key_s = gi_resp[8:-6].decode("ascii")
        gi_back_req = f"SSSSGI001SU{key_s}".encode("ascii")
        gi_back_resp = self.hsm.process_raw_message(gi_back_req)
        self.assertTrue(gi_back_resp.startswith(b"SSSSGJ00"))

    def test_kw_tr31_key_block_generation(self):
        # Generate KBMK (ZMK) under LMK
        zmk_resp = self.hsm.process_raw_message(b"SSSSA00000U")
        kbmk_hex = zmk_resp[8:8+33].decode("ascii")

        hdr = "S008021TB00E0000"
        kw_req = f"SSSSKW001{kbmk_hex}{hdr}".encode("ascii")
        kw_resp = self.hsm.process_raw_message(kw_req)
        self.assertTrue(kw_resp.startswith(b"SSSSKX00"))
        self.assertIn(b"S008021TB00E0000", kw_resp)

    def test_scheme_t_zmk_a6_and_kw(self):
        # 1. 24-byte ZMK (Scheme 'T') key import/translation (A6) and TR-31 export (KW)
        zmk_t_resp = self.hsm.process_raw_message(b"SSSSA00000T")
        self.assertTrue(zmk_t_resp.startswith(b"SSSSA100T"))
        zmk_t_hex = zmk_t_resp[8:8+49].decode("ascii")

        # A6 with 24-byte Scheme 'T' ZMK
        a6_req = f"SSSSA6001{zmk_t_hex}U11223344556677889900AABBCCDDEEFFU".encode("ascii")
        a6_resp = self.hsm.process_raw_message(a6_req)
        self.assertTrue(a6_resp.startswith(b"SSSSA700"))

        # KW with 24-byte Scheme 'T' ZMK
        hdr = "S008021TB00E0000"
        kw_req = f"SSSSKW001{zmk_t_hex}{hdr}".encode("ascii")
        kw_resp = self.hsm.process_raw_message(kw_req)
        self.assertTrue(kw_resp.startswith(b"SSSSKX00"))

    def test_a0_mode1_scheme_s_tr31_generation(self):
        # 2. A0 Mode 1 with Scheme 'S' TR-31 Key Block generation
        zmk_resp = self.hsm.process_raw_message(b"SSSSA00000U")
        zmk_u = zmk_resp[8:8+33].decode("ascii")

        a0_s_resp = self.hsm.process_raw_message(f"SSSSA01001S;1{zmk_u}".encode("ascii"))
        self.assertTrue(a0_s_resp.startswith(b"SSSSA100S"))

        # Extract TR-31 block wrapped under ZMK
        zmk_scheme, zmk_enc_bytes = _parse_key_payload(zmk_u)
        zmk_raw = self.hsm.lmk_engine.decrypt_under_lmk(zmk_enc_bytes, variant=1)
        # a0_s_resp body starts at index 8: key_lmk_hex (80 chars) + key_zmk_hex (80 chars) + kcv (6 chars)
        kb_zmk_str = a0_s_resp[8+80:8+80+80].decode("ascii")
        hdr_obj, clear_key = TR31KeyBlock.unwrap(kb_zmk_str, zmk_raw)
        self.assertEqual(len(clear_key), 16)
        self.assertEqual(hdr_obj.key_usage, "21")

    def test_tr31_malformed_payload_decryption(self):
        # 3. Malformed TR-31 payload decryption returning '13' (without crash)
        import Crypto.Cipher.DES3
        from binascii import hexlify
        kbmk = b"\x05" * 16
        hdr_str = "S004821TB00N0000"
        corrupt_payload_hex = "11223344556677889900"  # 10 bytes (unaligned)
        mac_data = (hdr_str + corrupt_payload_hex).encode("ascii")
        k_enc, k_mac = TR31KeyBlock._derive_keys(kbmk, "T")
        mac_cipher = Crypto.Cipher.DES3.new(k_mac[:16], Crypto.Cipher.DES3.MODE_CBC, iv=b"\x00"*8)
        mac_data += b"\x00" * (8 - (len(mac_data) % 8))
        mac_hex = hexlify(mac_cipher.encrypt(mac_data)[-8:]).upper().decode("ascii")
        corrupt_kb = hdr_str + corrupt_payload_hex + mac_hex

        with self.assertRaises(PayShieldException) as cm:
            TR31KeyBlock.unwrap(corrupt_kb, kbmk)
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_KEY_BLOCK)

    def test_tr31_malformed_payload_hex(self):
        # 4. Malformed TR-31 payload hex returning '13'
        kbmk = b"\x05" * 16
        hdr_str = "S004821TB00N0000"
        corrupt_kb = hdr_str + "ZZZZZZZZZZZZZZZZ" + "1234567890ABCDEF"
        with self.assertRaises(PayShieldException) as cm:
            TR31KeyBlock.unwrap(corrupt_kb, kbmk)
        self.assertEqual(cm.exception.error_code, ErrorCodes.INVALID_KEY_BLOCK)

    def test_a0_invalid_key_type_999(self):
        # Invalid key type is standard error 04.
        resp = self.hsm.process_raw_message(b"SSSSA00999U")
        self.assertEqual(resp, b"SSSSA104")

    def test_bu_invalid_key_type_validation(self):
        # BU command with non-numeric / invalid key types ('ABC', 'FFFF', '999')
        for invalid_kt in ("ABC", "FFFF", "999"):
            req = f"SSSSBU{invalid_kt}U11223344556677889900AABBCCDDEEFF".encode("ascii")
            resp = self.hsm.process_raw_message(req)
            self.assertEqual(resp, b"SSSSBV04", f"BU failed for invalid key type: {invalid_kt}")

    def test_dynamic_tr31_block_length_extraction(self):
        from pythales.commands.key_mgmt import _extract_key_string
        for length in (48, 64, 72, 80, 88, 96, 112, 128):
            block = f"S{length:04d}21TB00E0000" + "0" * (length - 16) + "TRAILING"
            extracted, trailing = _extract_key_string(block)
            self.assertEqual(len(extracted), length)
            self.assertEqual(trailing, "TRAILING")

    def test_tr31_optional_headers_unwrap(self):
        import os
        hdr = TR31Header("S", 86, "21", "T", "B", "00", "E", optional_headers=b"PB0100")
        kbmk = os.urandom(16)
        clear_key_orig = os.urandom(16)
        kb = TR31KeyBlock.wrap(clear_key_orig, hdr, kbmk)
        unwrapped_hdr, unwrapped_key = TR31KeyBlock.unwrap(kb, kbmk)
        self.assertEqual(unwrapped_key, clear_key_orig)
        self.assertEqual(unwrapped_hdr.optional_headers, b"PB0100")

    def test_a6_target_scheme_expansion(self):
        # Generate ZMK under LMK
        zmk_resp = self.hsm.process_raw_message(b"SSSSA00000U")
        zmk_u = zmk_resp[8:8+33].decode("ascii")

        # Generate ZPK under ZMK
        zpk_m1_resp = self.hsm.process_raw_message(f"SSSSA01001U;1{zmk_u}".encode("ascii"))
        zpk_zmk = zpk_m1_resp[8+33:8+33+33].decode("ascii")

        # LMK output schemes represented by A7 are Z/U/T/S.
        for target_sch in ("Z", "U", "T", "S"):
            a6_req = f"SSSSA6001{zmk_u}{zpk_zmk}{target_sch}".encode("ascii")
            a6_resp = self.hsm.process_raw_message(a6_req)
            self.assertTrue(a6_resp.startswith(b"SSSSA700"), f"A6 failed for target scheme {target_sch}: {a6_resp}")

    def test_tr31_opt_count_zero_reproduction(self):
        from binascii import unhexlify
        kbmk_aes = unhexlify('1438201138add9c3613d47e62c732796')
        key_aes = unhexlify('a0eeb20e84022a9db51a088b7cbd13bc553b69f495d4c662d2169249d67c7283')
        kb_str = 'S0128C0AB00E0000AF100411D9B40578447E78DEBBEE43E9E50CC036188CA830503CB16B28F6DB69E4EF6D2DAC04B025F177D96DE9FABC99F8865B25B9089C7A'
        hdr_obj = parse_header(kb_str)
        self.assertEqual(hdr_obj.optional_headers, b'')
        unwrapped_hdr, unwrapped_key = TR31KeyBlock.unwrap(kb_str, kbmk_aes)
        self.assertEqual(unwrapped_hdr.optional_headers, b'')
        self.assertEqual(unwrapped_key, key_aes)

    def test_tr31_random_aes_wrap_unwrap_loop(self):
        import os
        hdr = TR31Header("S", 0, "C0", "A", "B", "00", "E")
        for _ in range(100):
            kbmk = os.urandom(16)
            clear_key = os.urandom(16)
            kb = TR31KeyBlock.wrap(clear_key, hdr, kbmk)
            unwrapped_hdr, unwrapped_key = TR31KeyBlock.unwrap(kb, kbmk)
            self.assertEqual(unwrapped_key, clear_key)
            self.assertEqual(unwrapped_hdr.optional_headers, b'')


class TestMilestoneM3PinAndCardVerify(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="SSSS", skip_parity=True)

    def test_ca_cb_translate_pin_block_format_01_and_48(self):
        from pythales.commands.pin import encrypt_pin_block, decrypt_pin_block, _decrypt_key
        # Generate Source ZPK and Dest ZPK
        zpk1_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk1_hex = zpk1_resp[8:8+33].decode("ascii")
        zpk1_bytes = _decrypt_key(self.hsm, zpk1_hex, variant=2)

        zpk2_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk2_hex = zpk2_resp[8:8+33].decode("ascii")
        zpk2_bytes = _decrypt_key(self.hsm, zpk2_hex, variant=2)

        # Test Format '01' (Format 0)
        pin1 = "1234"
        pan1 = "407000000010"
        src_pb_01 = encrypt_pin_block(zpk1_bytes, pin1, "01", pan1)
        ca_req_01 = f"SSSSCA{zpk1_hex}{zpk2_hex}12{src_pb_01}0101{pan1}".encode("ascii")
        ca_resp_01 = self.hsm.process_raw_message(ca_req_01)
        self.assertTrue(ca_resp_01.startswith(b"SSSSCB00"))

        dst_pb_01 = ca_resp_01[8:8+16].decode("ascii")
        dec_pin_01 = decrypt_pin_block(zpk2_bytes, dst_pb_01, "01", pan1)
        self.assertEqual(dec_pin_01, pin1)

        # Test Format '48' (Format 4)
        pin2 = "5678"
        src_pb_48 = encrypt_pin_block(zpk1_bytes, pin2, "48", pan1)
        ca_req_48 = f"SSSSCA{zpk1_hex}{zpk2_hex}12{src_pb_48}4848{pan1}".encode("ascii")
        ca_resp_48 = self.hsm.process_raw_message(ca_req_48)
        self.assertTrue(ca_resp_48.startswith(b"SSSSCB00"))

        dst_pb_48 = ca_resp_48[8:8+32].decode("ascii")
        dec_pin_48 = decrypt_pin_block(zpk2_bytes, dst_pb_48, "48", pan1)
        self.assertEqual(dec_pin_48, pin2)

    def test_dc_dd_verify_customer_pin_format_01_and_48(self):
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from pythales.crypto.tools import get_visa_pvv
        from binascii import hexlify

        # Generate TPK and PVK
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)
        if len(pvk_bytes) < 16:
            pvk_bytes = (pvk_bytes + pvk_bytes)[:16]
        raw_pvk_hex = hexlify(pvk_bytes[:16]).decode("ascii").upper()


        pan = "407000000010"
        pvki = "1"

        # Format '01'
        pin1 = "1234"
        pb_01 = encrypt_pin_block(tpk_bytes, pin1, "01", pan)
        pvv_01 = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin1.encode("ascii"), raw_pvk_hex.encode("ascii")).decode("ascii")

        dc_req_01 = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan}{pvki}{pvv_01}".encode("ascii")
        dc_resp_01 = self.hsm.process_raw_message(dc_req_01)
        self.assertEqual(dc_resp_01, b"SSSSDD00")

        # Invalid PVV format 01
        dc_bad_01 = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan}{pvki}9999".encode("ascii")
        dc_bad_resp_01 = self.hsm.process_raw_message(dc_bad_01)
        self.assertEqual(dc_bad_resp_01, b"SSSSDD01")

        # Format '48'
        pin2 = "4321"
        pb_48 = encrypt_pin_block(tpk_bytes, pin2, "48", pan)
        pvv_48 = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin2.encode("ascii"), raw_pvk_hex.encode("ascii")).decode("ascii")

        dc_req_48 = f"SSSSDC{tpk_hex}{pvk_hex}{pb_48}48{pan}{pvki}{pvv_48}".encode("ascii")
        dc_resp_48 = self.hsm.process_raw_message(dc_req_48)
        self.assertEqual(dc_resp_48, b"SSSSDD00")

        # Invalid PVV format 48
        dc_bad_48 = f"SSSSDC{tpk_hex}{pvk_hex}{pb_48}48{pan}{pvki}9999".encode("ascii")
        dc_bad_resp_48 = self.hsm.process_raw_message(dc_bad_48)
        self.assertEqual(dc_bad_resp_48, b"SSSSDD01")

    def test_ec_ed_translate_pin_block_under_lmk_format_01_and_48(self):
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from pythales.crypto.tools import get_visa_pvv
        from binascii import hexlify

        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)
        if len(pvk_bytes) < 16:
            pvk_bytes = (pvk_bytes + pvk_bytes)[:16]
        raw_pvk_hex = hexlify(pvk_bytes[:16]).decode("ascii").upper()


        pan = "407000000010"
        pvki = "1"
        pin = "1384"
        pvv = get_visa_pvv(pan.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), raw_pvk_hex.encode("ascii")).decode("ascii")

        # Format 01
        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan)
        ec_req_01 = f"SSSSEC{zpk_hex}{pvk_hex}{pb_01}01{pan}{pvki}{pvv}".encode("ascii")
        ec_resp_01 = self.hsm.process_raw_message(ec_req_01)
        self.assertEqual(ec_resp_01, b"SSSSED00")

        # Format 48
        pb_48 = encrypt_pin_block(zpk_bytes, pin, "48", pan)
        ec_req_48 = f"SSSSEC{zpk_hex}{pvk_hex}{pb_48}48{pan}{pvki}{pvv}".encode("ascii")
        ec_resp_48 = self.hsm.process_raw_message(ec_req_48)
        self.assertEqual(ec_resp_48, b"SSSSED00")

    def test_ba_bb_generate_pin_and_encrypt(self):
        from pythales.commands.pin import decrypt_pin_block, _decrypt_key

        # Random PIN 4 digits
        ba_req4 = b"SSSSBA04"
        ba_resp4 = self.hsm.process_raw_message(ba_req4)
        self.assertTrue(ba_resp4.startswith(b"SSSSBB00"))
        pin4 = ba_resp4[8:].decode("ascii")
        self.assertEqual(len(pin4), 4)
        self.assertTrue(pin4.isdigit())

        # Random PIN 8 digits
        ba_req8 = b"SSSSBA08"
        ba_resp8 = self.hsm.process_raw_message(ba_req8)
        self.assertTrue(ba_resp8.startswith(b"SSSSBB00"))
        pin8 = ba_resp8[8:].decode("ascii")
        self.assertEqual(len(pin8), 8)
        self.assertTrue(pin8.isdigit())

        # Encrypt clear PIN under ZPK
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pan = "407000000010"
        ba_enc_req = f"SSSSBA{zpk_hex}{pan}1234".encode("ascii")
        ba_enc_resp = self.hsm.process_raw_message(ba_enc_req)
        self.assertTrue(ba_enc_resp.startswith(b"SSSSBB00"))

        payload = ba_enc_resp[8:].decode("ascii")
        clear_pin_out = payload[:4]
        enc_pb = payload[4:20]
        self.assertEqual(clear_pin_out, "1234")
        dec_pin = decrypt_pin_block(zpk_bytes, enc_pb, "01", pan)
        self.assertEqual(dec_pin, "1234")

    def test_ee_ef_ibm_3624_offset_verification(self):
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from binascii import unhexlify, hexlify
        import Crypto.Cipher.DES3

        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        customer_pin = "1234"
        pan = "407000000010"
        pb_01 = encrypt_pin_block(zpk_bytes, customer_pin, "01", pan)

        dec_table = "0123456789012345"
        val_data = "4070000000100000"

        val_bytes = unhexlify(val_data)
        cipher = Crypto.Cipher.DES3.new(pvk_bytes[:16], Crypto.Cipher.DES3.MODE_ECB)
        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:4]
        offset = "".join([str((int(customer_pin[i]) - int(natural_pin[i])) % 10) for i in range(4)])

        # Verify correct offset -> EE returns SSSSEF00
        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_01}01{pan}{dec_table}{offset}{val_data}".encode("ascii")
        ee_resp = self.hsm.process_raw_message(ee_req)
        self.assertEqual(ee_resp, b"SSSSEF00")

        # Verify incorrect offset -> EE returns SSSSEF01
        ee_bad_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_01}01{pan}{dec_table}9999{val_data}".encode("ascii")
        ee_bad_resp = self.hsm.process_raw_message(ee_bad_req)
        self.assertEqual(ee_bad_resp, b"SSSSEF01")

    def test_cw_cx_cvv_generation_with_delimiter(self):
        cvk_resp = self.hsm.process_raw_message(b"SSSSA00003U")  # KeyType 003 CVK
        cvk_hex = cvk_resp[8:8+33].decode("ascii")

        # Delimited CW request
        cw_delim_req = f"SSSSCW{cvk_hex}4575272222567122;2010000".encode("ascii")
        cw_delim_resp = self.hsm.process_raw_message(cw_delim_req)
        self.assertTrue(cw_delim_resp.startswith(b"SSSSCX00"))
        cvv_delim = cw_delim_resp[8:].decode("ascii")
        self.assertEqual(len(cvv_delim), 3)

        # Fixed CW request
        cw_fixed_req = f"SSSSCW{cvk_hex}45752722225671222010000".encode("ascii")
        cw_fixed_resp = self.hsm.process_raw_message(cw_fixed_req)
        self.assertTrue(cw_fixed_resp.startswith(b"SSSSCX00"))

    def test_cy_cz_cvv_verification_with_delimiter(self):
        cvk_resp = self.hsm.process_raw_message(b"SSSSA00003U")
        cvk_hex = cvk_resp[8:8+33].decode("ascii")

        cw_req = f"SSSSCW{cvk_hex}4575272222567122;2010000".encode("ascii")
        cw_resp = self.hsm.process_raw_message(cw_req)
        cvv = cw_resp[8:].decode("ascii")

        # CY match with delimiter
        cy_match_req = f"SSSSCY{cvk_hex}{cvv}4575272222567122;2010000".encode("ascii")
        cy_match_resp = self.hsm.process_raw_message(cy_match_req)
        self.assertEqual(cy_match_resp, b"SSSSCZ00")

        # CY mismatch with delimiter
        cy_mismatch_req = f"SSSSCY{cvk_hex}9994575272222567122;2010000".encode("ascii")
        cy_mismatch_resp = self.hsm.process_raw_message(cy_mismatch_req)
        self.assertEqual(cy_mismatch_resp, b"SSSSCZ01")

    def test_format_48_iso_vector_aes128(self):
        from pythales.commands.pin import encrypt_pin_block, decrypt_pin_block
        key16 = b"\x01" * 16
        pan = "4575272222567122"
        pin = "1234"
        expected_cipher = "F480606AA7AF374FDC1947194E91B6BD"

        enc_pb = encrypt_pin_block(key16, pin, "48", pan)
        self.assertEqual(enc_pb, expected_cipher)
        dec_pin = decrypt_pin_block(key16, expected_cipher, "48", pan)
        self.assertEqual(dec_pin, pin)

    def test_dc_dd_format_48_16_digit_pan(self):
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from pythales.crypto.tools import get_visa_pvv
        from binascii import hexlify

        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_16 = "4575272222567122"
        pin = "4321"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan_16.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_48 = encrypt_pin_block(tpk_bytes, pin, "48", pan_16)

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_48}48{pan_16}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD00")

    def test_ec_ed_format_48_16_digit_pan(self):
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from pythales.crypto.tools import get_visa_pvv
        from binascii import hexlify

        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_16 = "4575272222567122"
        pin = "1234"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan_16.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_48 = encrypt_pin_block(zpk_bytes, pin, "48", pan_16)

        ec_req = f"SSSSEC{zpk_hex}{pvk_hex}{pb_48}48{pan_16}{pvki}{calc_pvv}".encode("ascii")
        ec_resp = self.hsm.process_raw_message(ec_req)
        self.assertEqual(ec_resp, b"SSSSED00")

    def test_ee_ef_6digit_pin_offset(self):
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from binascii import unhexlify, hexlify
        import Crypto.Cipher.DES3

        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pin = "123456"
        pan = "407000000010"
        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan)

        dec_table = "0123456789012345"
        val_data = "4070000000100000"

        val_bytes = unhexlify(val_data)
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        cipher = Crypto.Cipher.DES3.new(pvk_16, Crypto.Cipher.DES3.MODE_ECB)
        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:6]
        offset_6 = "".join([str((int(pin[i]) - int(natural_pin[i])) % 10) for i in range(6)])

        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_01}01{pan}{dec_table}{offset_6}{val_data}".encode("ascii")
        ee_resp = self.hsm.process_raw_message(ee_req)
        self.assertEqual(ee_resp, b"SSSSEF00")

    def test_invalid_pin_block_format_99_returns_error_21(self):
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}00000000000000009940700000001010000".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD21")

    def test_fmt01_pan_pvv_collision_04_48_parsed_as_fmt01(self):
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from pythales.crypto.tools import get_visa_pvv
        from binascii import hexlify

        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_ending_48 = "4070000000010148"
        pin = "1234"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan_ending_48.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_01 = encrypt_pin_block(tpk_bytes, pin, "01", pan_ending_48)

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan_ending_48}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD00")

    def test_ee_ef_format_48_16_digit_pan(self):
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from binascii import unhexlify, hexlify
        import Crypto.Cipher.DES3

        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pin = "1234"
        pan_16 = "4070000000010100"
        pb_48 = encrypt_pin_block(zpk_bytes, pin, "48", pan_16)

        dec_table = "0123456789012345"
        val_data = "4070000000010000"

        val_bytes = unhexlify(val_data)
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        cipher = Crypto.Cipher.DES3.new(pvk_16, Crypto.Cipher.DES3.MODE_ECB)
        enc_val_bytes = cipher.encrypt(val_bytes[:8])
        enc_val_hex = hexlify(enc_val_bytes).decode("ascii").upper()

        natural_pin = "".join([dec_table[int(c, 16)] for c in enc_val_hex])[:4]
        offset_4 = "".join([str((int(pin[i]) - int(natural_pin[i])) % 10) for i in range(4)])

        ee_req = f"SSSSEE{zpk_hex}{pvk_hex}{pb_48}48{pan_16}{dec_table}{offset_4}{val_data}".encode("ascii")
        ee_resp = self.hsm.process_raw_message(ee_req)
        self.assertEqual(ee_resp, b"SSSSEF00")

    def test_remediation_1_ca_cb_omitted_dst_fmt_with_standard_pan(self):
        """
        1. CA/CB: When dst_fmt is omitted, PAN starting with '40' (e.g. '407000000010')
        is not mistaken for dst_fmt code '40'.
        """
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        zpk1_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk1_hex = zpk1_resp[8:8+33].decode("ascii")
        zpk1_bytes = _decrypt_key(self.hsm, zpk1_hex, variant=2)

        zpk2_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk2_hex = zpk2_resp[8:8+33].decode("ascii")

        pan = "407000000010"
        pb_01 = encrypt_pin_block(zpk1_bytes, "1234", "01", pan)

        ca_req = f"SSSSCA{zpk1_hex}{zpk2_hex}12{pb_01}01{pan}".encode("ascii")
        ca_resp = self.hsm.process_raw_message(ca_req)
        self.assertTrue(ca_resp.startswith(b"SSSSCB00"))

    def test_remediation_2_ba_bb_16_digit_pan_clear_pin(self):
        """
        2. BA/BB: Encrypt clear PIN under ZPK with 16-digit PAN does not bleed PAN digits into clear_pin.
        """
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")

        pan_16 = "4575272222567122"
        clear_pin = "1234"

        ba_req = f"SSSSBA{zpk_hex}{pan_16}{clear_pin}".encode("ascii")
        ba_resp = self.hsm.process_raw_message(ba_req)
        self.assertEqual(ba_resp[:12], b"SSSSBB001234")

    def test_remediation_3_dc_dd_visa_pvv_16_digit_pan(self):
        """
        3. DC/DD: Verify PIN - Visa PVV passes full 16-digit PAN to get_visa_pvv.
        """
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from pythales.crypto.tools import get_visa_pvv
        from binascii import hexlify
        tpk_resp = self.hsm.process_raw_message(b"SSSSA00002U")
        tpk_hex = tpk_resp[8:8+33].decode("ascii")
        tpk_bytes = _decrypt_key(self.hsm, tpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_16 = "4575272222567122"
        pin = "4321"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan_16.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_01 = encrypt_pin_block(tpk_bytes, pin, "01", pan_16)

        dc_req = f"SSSSDC{tpk_hex}{pvk_hex}{pb_01}01{pan_16}{pvki}{calc_pvv}".encode("ascii")
        dc_resp = self.hsm.process_raw_message(dc_req)
        self.assertEqual(dc_resp, b"SSSSDD00")

    def test_remediation_4_ec_ed_visa_pvv_16_digit_pan(self):
        """
        4. EC/ED: Verify IBM PIN / PVV passes full 16-digit PAN to get_visa_pvv.
        """
        from pythales.commands.pin import encrypt_pin_block, _decrypt_key
        from pythales.crypto.tools import get_visa_pvv
        from binascii import hexlify
        zpk_resp = self.hsm.process_raw_message(b"SSSSA00001U")
        zpk_hex = zpk_resp[8:8+33].decode("ascii")
        zpk_bytes = _decrypt_key(self.hsm, zpk_hex, variant=2)

        pvk_resp = self.hsm.process_raw_message(b"SSSSA00005U")
        pvk_hex = pvk_resp[8:8+33].decode("ascii")
        pvk_bytes = _decrypt_key(self.hsm, pvk_hex, variant=3)

        pan_16 = "4575272222567122"
        pin = "1234"
        pvki = "1"
        pvk_16 = (pvk_bytes + pvk_bytes)[:16]
        pvk_hex_16 = hexlify(pvk_16).decode("ascii").upper()

        calc_pvv = get_visa_pvv(pan_16.encode("ascii"), pvki.encode("ascii"), pin.encode("ascii"), pvk_hex_16.encode("ascii")).decode("ascii")
        pb_01 = encrypt_pin_block(zpk_bytes, pin, "01", pan_16)

        ec_req = f"SSSSEC{zpk_hex}{pvk_hex}{pb_01}01{pan_16}{pvki}{calc_pvv}".encode("ascii")
        ec_resp = self.hsm.process_raw_message(ec_req)
        self.assertEqual(ec_resp, b"SSSSED00")

    def test_remediation_5_cw_cx_multiple_semicolons(self):
        """
        5. CW/CX: Generate CVV with multiple ';' delimiters (PAN;EXP;SVC).
        """
        cvk_resp = self.hsm.process_raw_message(b"SSSSA00402U")
        cvk_hex = cvk_resp[8:8+33].decode("ascii")

        cw_req = f"SSSSCW{cvk_hex}4575272222567122;2512;999".encode("ascii")
        cw_resp = self.hsm.process_raw_message(cw_req)
        self.assertTrue(cw_resp.startswith(b"SSSSCX00"))

    def test_remediation_6_cy_cz_semicolons_with_cvv_at_end(self):
        """
        6. CY/CZ: Verify CVV when payload contains semicolons with CVV at end (PAN;EXP;SVC;CVV).
        """
        from pythales.commands.card_verify import _decrypt_cvk, calculate_cvv
        cvk_resp = self.hsm.process_raw_message(b"SSSSA00402U")
        cvk_hex = cvk_resp[8:8+33].decode("ascii")
        cvk_bytes = _decrypt_cvk(self.hsm, cvk_hex)

        pan = "4575272222567122"
        exp_date = "2512"
        svc = "999"
        expected_cvv = calculate_cvv(cvk_bytes, pan, exp_date, svc)

        cy_req = f"SSSSCY{cvk_hex}{pan};{exp_date};{svc};{expected_cvv}".encode("ascii")
        cy_resp = self.hsm.process_raw_message(cy_req)
        self.assertEqual(cy_resp, b"SSSSCZ00")

    def test_remediation_7_single_length_key_scheme_decryption(self):
        """
        7. Single-length key decryption in _decrypt_key and _decrypt_cvk with scheme prefix 'Z' (and 'D', 'E', 'A').
        """
        from pythales.commands.pin import _decrypt_key
        from pythales.commands.card_verify import _decrypt_cvk
        from binascii import hexlify

        # Test _decrypt_key with single-length key (8 bytes) under schemes 'Z', 'D', 'E', 'A'
        clear_key = b"12345678"
        enc_bytes_v2 = self.hsm.lmk_engine.encrypt_under_lmk(clear_key, variant=2)
        enc_hex_v2 = hexlify(enc_bytes_v2).decode("ascii").upper()

        for scheme in ("Z", "D", "E", "A"):
            key_str = f"{scheme}{enc_hex_v2}"
            decrypted = _decrypt_key(self.hsm, key_str, variant=2)
            self.assertEqual(decrypted, clear_key, f"_decrypt_key failed for scheme {scheme}")

        # Test _decrypt_cvk with single-length key (8 bytes) under schemes 'Z', 'D', 'E', 'A'
        clear_cvk = b"87654321"
        enc_bytes_v4 = self.hsm.lmk_engine.encrypt_under_lmk(clear_cvk, variant=4)
        enc_hex_v4 = hexlify(enc_bytes_v4).decode("ascii").upper()

        for scheme in ("Z", "D", "E", "A"):
            key_str = f"{scheme}{enc_hex_v4}"
            decrypted = _decrypt_cvk(self.hsm, key_str)
            self.assertEqual(decrypted, clear_cvk, f"_decrypt_cvk failed for scheme {scheme}")


class TestMilestoneM4DataProtectionAndEMV(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header="SSSS")

    def test_m0_m2_all_modes_ecb_cbc_ctr_ff1(self):
        """Test M0/M1 and M2/M3 across modes '00', '01', '06', '11'."""
        gen_dek = self.hsm.process_raw_message(b"SSSSA00008U")
        self.assertTrue(gen_dek.startswith(b"SSSSA100"))
        dek_hex = gen_dek[8:8+33].decode("ascii")

        # 1. Mode '00' (ECB)
        data_hex = "504159534849454C44313233343536"  # 15 bytes
        m0_req = f"SSSSM0{dek_hex}00000F{data_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))
        enc_hex = m0_resp[8:].decode("ascii")

        enc_len = len(enc_hex) // 2
        m2_req = f"SSSSM2{dek_hex}00{enc_len:04X}{enc_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        dec_hex = m2_resp[8:].decode("ascii")
        self.assertEqual(dec_hex, data_hex)

        # 2. Mode '01' (CBC) with 16-hex IV
        iv_hex = "0102030405060708"
        m0_cbc_req = f"SSSSM0{dek_hex}01000F{data_hex}{iv_hex}".encode("ascii")
        m0_cbc_resp = self.hsm.process_raw_message(m0_cbc_req)
        self.assertTrue(m0_cbc_resp.startswith(b"SSSSM100"))
        enc_cbc_hex = m0_cbc_resp[8:].decode("ascii")

        m2_cbc_req = f"SSSSM2{dek_hex}01{len(enc_cbc_hex)//2:04X}{enc_cbc_hex}{iv_hex}".encode("ascii")
        m2_cbc_resp = self.hsm.process_raw_message(m2_cbc_req)
        self.assertTrue(m2_cbc_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_cbc_resp[8:].decode("ascii"), data_hex)

        # 3. Mode '06' (CTR) with 16-hex IV
        m0_ctr_req = f"SSSSM0{dek_hex}06000F{data_hex}{iv_hex}".encode("ascii")
        m0_ctr_resp = self.hsm.process_raw_message(m0_ctr_req)
        self.assertTrue(m0_ctr_resp.startswith(b"SSSSM100"))
        enc_ctr_hex = m0_ctr_resp[8:].decode("ascii")

        m2_ctr_req = f"SSSSM2{dek_hex}06{len(enc_ctr_hex)//2:04X}{enc_ctr_hex}{iv_hex}".encode("ascii")
        m2_ctr_resp = self.hsm.process_raw_message(m2_ctr_req)
        self.assertTrue(m2_ctr_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_ctr_resp[8:].decode("ascii"), data_hex)

        # 4. Mode '11' (FF1 FPE)
        numeric_str = "1234567890123456"
        m0_ff1_req = f"SSSSM0{dek_hex}110010{numeric_str}".encode("ascii")
        m0_ff1_resp = self.hsm.process_raw_message(m0_ff1_req)
        self.assertTrue(m0_ff1_resp.startswith(b"SSSSM100"))
        enc_ff1 = m0_ff1_resp[8:].decode("ascii")
        self.assertEqual(len(enc_ff1), len(numeric_str))
        self.assertNotEqual(enc_ff1, numeric_str)

        m2_ff1_req = f"SSSSM2{dek_hex}110010{enc_ff1}".encode("ascii")
        m2_ff1_resp = self.hsm.process_raw_message(m2_ff1_req)
        self.assertTrue(m2_ff1_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_ff1_resp[8:].decode("ascii"), numeric_str)

    def test_m4_m5_translate_data_block(self):
        """Test M4/M5 translate data block from DEK1 CBC to DEK2 ECB."""
        gen_dek1 = self.hsm.process_raw_message(b"SSSSA00008U")
        dek1_hex = gen_dek1[8:8+33].decode("ascii")
        gen_dek2 = self.hsm.process_raw_message(b"SSSSA00008U")
        dek2_hex = gen_dek2[8:8+33].decode("ascii")

        data_hex = "41424344454647483132333435363738"
        iv_hex = "1122334455667788"

        # Encrypt under DEK1 CBC mode
        m0_req = f"SSSSM0{dek1_hex}010010{data_hex}{iv_hex}".encode("ascii")
        enc1_hex = self.hsm.process_raw_message(m0_req)[8:].decode("ascii")

        # Translate from DEK1 (CBC mode '01') to DEK2 (ECB mode '00')
        enc1_len = len(enc1_hex) // 2
        m4_req = f"SSSSM4{dek1_hex}{dek2_hex}0100{enc1_len:04X}{enc1_hex}{iv_hex}0000000000000000".encode("ascii")
        m4_resp = self.hsm.process_raw_message(m4_req)
        self.assertTrue(m4_resp.startswith(b"SSSSM500"))
        enc2_hex = m4_resp[8:].decode("ascii")

        # Decrypt enc2 under DEK2 ECB mode
        m2_req = f"SSSSM2{dek2_hex}00{len(enc2_hex)//2:04X}{enc2_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_m6_m7_m8_m9_mac_gen_and_verify(self):
        """Test M6/M7 generate MAC and M8/M9 verify MAC (ISO Alg 1, Alg 3, CMAC)."""
        gen_tak = self.hsm.process_raw_message(b"SSSSA0000AU")
        tak_hex = gen_tak[8:8+33].decode("ascii")
        data_hex = "0102030405060708090A0B0C"

        # 1. ISO 9797 Alg 1 ('00')
        m6_alg1 = f"SSSSM6{tak_hex}00000C{data_hex}".encode("ascii")
        m7_alg1_resp = self.hsm.process_raw_message(m6_alg1)
        self.assertTrue(m7_alg1_resp.startswith(b"SSSSM700"))
        mac_alg1_hex = m7_alg1_resp[8:].decode("ascii")

        m8_alg1 = f"SSSSM8{tak_hex}00000C{mac_alg1_hex}{data_hex}".encode("ascii")
        m9_alg1_resp = self.hsm.process_raw_message(m8_alg1)
        self.assertEqual(m9_alg1_resp, b"SSSSM900")

        # 2. ISO 9797 Alg 3 ('01')
        m6_alg3 = f"SSSSM6{tak_hex}01000C{data_hex}".encode("ascii")
        m7_alg3_resp = self.hsm.process_raw_message(m6_alg3)
        self.assertTrue(m7_alg3_resp.startswith(b"SSSSM700"))
        mac_alg3_hex = m7_alg3_resp[8:].decode("ascii")

        m8_alg3 = f"SSSSM8{tak_hex}01000C{mac_alg3_hex}{data_hex}".encode("ascii")
        m9_alg3_resp = self.hsm.process_raw_message(m8_alg3)
        self.assertEqual(m9_alg3_resp, b"SSSSM900")

        # 3. CMAC ('02')
        m6_cmac = f"SSSSM6{tak_hex}02000C{data_hex}".encode("ascii")
        m7_cmac_resp = self.hsm.process_raw_message(m6_cmac)
        self.assertTrue(m7_cmac_resp.startswith(b"SSSSM700"))
        mac_cmac_hex = m7_cmac_resp[8:].decode("ascii")

        m8_cmac = f"SSSSM8{tak_hex}02000C{mac_cmac_hex}{data_hex}".encode("ascii")
        m9_cmac_resp = self.hsm.process_raw_message(m8_cmac)
        self.assertEqual(m9_cmac_resp, b"SSSSM900")

        # 4. M8 Verification Mismatch -> Error Code '10'
        bad_mac = "FFFFFFFFFFFFFFFF"
        m8_bad = f"SSSSM8{tak_hex}00000C{bad_mac}{data_hex}".encode("ascii")
        m9_bad_resp = self.hsm.process_raw_message(m8_bad)
        self.assertTrue(m9_bad_resp.startswith(b"SSSSM910"))

    def test_kq_kr_emv_arqc_arpc(self):
        """Test KQ/KR EMV ARQC generation, verification, and ARPC generation."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        pan = "4000123456789010"
        psn = "01"
        atc_hex = "0005"
        txn_data_hex = "00000000100000000000000008400000000000084021081100123456"
        txn_len = len(txn_data_hex) // 2

        # 1. Mode 1: Generate ARQC
        kq1_req = f"SSSSKQ1{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}".encode("ascii")
        kq1_resp = self.hsm.process_raw_message(kq1_req)
        self.assertTrue(kq1_resp.startswith(b"SSSSKR00"))
        arqc_hex = kq1_resp[8:].decode("ascii")
        self.assertEqual(len(arqc_hex), 16)

        # 2. Mode 0: Verify ARQC & Generate ARPC
        arc_hex = "3030"
        kq0_req = f"SSSSKQ0{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}{arqc_hex}{arc_hex}".encode("ascii")
        kq0_resp = self.hsm.process_raw_message(kq0_req)
        self.assertTrue(kq0_resp.startswith(b"SSSSKR00"))
        arpc_hex = kq0_resp[8:].decode("ascii")
        self.assertEqual(len(arpc_hex), 16)

        # 3. Mode 2: Verify ARQC only
        kq2_req = f"SSSSKQ2{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}{arqc_hex}".encode("ascii")
        kq2_resp = self.hsm.process_raw_message(kq2_req)
        self.assertEqual(kq2_resp, b"SSSSKR00")

        # 4. Bad ARQC verification failure -> Error Code '29'
        bad_arqc = "0011223344556677"
        kq_bad = f"SSSSKQ2{mdk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}{bad_arqc}".encode("ascii")
        kq_bad_resp = self.hsm.process_raw_message(kq_bad)
        self.assertTrue(kq_bad_resp.startswith(b"SSSSKR29"))

    def test_ku_kv_emv_script_encryption(self):
        """Test KU/KV EMV script encryption and decryption roundtrip."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        atc_hex = "0001"
        script_hex = "84240000081122334455667788"
        script_len = len(script_hex) // 2

        # KU Encrypt Script
        ku_req = f"SSSSKU{mdk_hex}{atc_hex}{script_len:04X}{script_hex}".encode("ascii")
        ku_resp = self.hsm.process_raw_message(ku_req)
        self.assertTrue(ku_resp.startswith(b"SSSSKV00"))
        enc_script_hex = ku_resp[8:].decode("ascii")

        # KV Decrypt Script
        enc_len = len(enc_script_hex) // 2
        kv_req = f"SSSSKV{mdk_hex}{atc_hex}{enc_len:04X}{enc_script_hex}".encode("ascii")
        kv_resp = self.hsm.process_raw_message(kv_req)
        self.assertTrue(kv_resp.startswith(b"SSSSKW00"))
        dec_script_hex = kv_resp[8:].decode("ascii")
        self.assertEqual(dec_script_hex, script_hex)

    def test_ky_kz_emv_script_integrity(self):
        """Test KY/KZ EMV script MAC generation."""
        gen_mdk = self.hsm.process_raw_message(b"SSSSA00000U")
        mdk_hex = gen_mdk[8:8+33].decode("ascii")

        atc_hex = "0002"
        script_hex = "841800000411223344"
        script_len = len(script_hex) // 2

        ky_req = f"SSSSKY{mdk_hex}{atc_hex}{script_len:04X}{script_hex}".encode("ascii")
        ky_resp = self.hsm.process_raw_message(ky_req)
        self.assertTrue(ky_resp.startswith(b"SSSSKZ00"))
        mac_hex = ky_resp[8:].decode("ascii")
        self.assertEqual(len(mac_hex), 16)

    def test_m0_ascii_plaintext_with_iv(self):
        """Test M0 encryption with 16 ASCII digit plaintext + 16 hex IV characters."""
        gen_dek = self.hsm.process_raw_message(b"SSSSA00008U")
        dek_hex = gen_dek[8:8+33].decode("ascii")

        plaintext_ascii = "1234567890123456"
        iv_hex = "0102030405060708"
        data_len = len(plaintext_ascii)

        # M0 CBC mode '01', 16 ASCII digits + 16 hex IV
        m0_req = f"SSSSM0{dek_hex}01{data_len:04X}{plaintext_ascii}{iv_hex}".encode("ascii")
        m0_resp = self.hsm.process_raw_message(m0_req)
        self.assertTrue(m0_resp.startswith(b"SSSSM100"))
        enc_hex = m0_resp[8:].decode("ascii")

        # Decrypt via M2 CBC mode '01' with the same IV
        enc_len = len(enc_hex) // 2
        m2_req = f"SSSSM2{dek_hex}01{enc_len:04X}{enc_hex}{iv_hex}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        dec_hex = m2_resp[8:].decode("ascii")
        dec_bytes = bytes.fromhex(dec_hex)
        self.assertEqual(dec_bytes, plaintext_ascii.encode("ascii"))

    def test_m4_translate_1char_ecb_to_1char_cbc(self):
        """Test M4 data translation with 1-char source mode '0' (ECB) and 1-char target mode '1' (CBC) with target IV."""
        gen_dek1 = self.hsm.process_raw_message(b"SSSSA00008U")
        dek1_hex = gen_dek1[8:8+33].decode("ascii")
        gen_dek2 = self.hsm.process_raw_message(b"SSSSA00008U")
        dek2_hex = gen_dek2[8:8+33].decode("ascii")

        data_hex = "11223344556677889900AABBCCDDEEFF"
        data_len = len(data_hex) // 2
        tgt_iv = "0102030405060708"

        # Encrypt under DEK1 ECB mode '0'
        m0_req = f"SSSSM0{dek1_hex}0{data_len:04X}{data_hex}".encode("ascii")
        enc1_hex = self.hsm.process_raw_message(m0_req)[8:].decode("ascii")
        enc1_len = len(enc1_hex) // 2

        # Translate M4: DEK1 (1-char mode '0') -> DEK2 (1-char mode '1') with target IV
        m4_req = f"SSSSM4{dek1_hex}{dek2_hex}01{enc1_len:04X}{enc1_hex}{tgt_iv}".encode("ascii")
        m4_resp = self.hsm.process_raw_message(m4_req)
        self.assertTrue(m4_resp.startswith(b"SSSSM500"))

        enc2_hex = m4_resp[8:].decode("ascii")
        enc2_len = len(enc2_hex) // 2

        # Decrypt under DEK2 CBC mode '01' with target IV
        m2_req = f"SSSSM2{dek2_hex}01{enc2_len:04X}{enc2_hex}{tgt_iv}".encode("ascii")
        m2_resp = self.hsm.process_raw_message(m2_req)
        self.assertTrue(m2_resp.startswith(b"SSSSM300"))
        self.assertEqual(m2_resp[8:].decode("ascii"), data_hex)

    def test_kq_arqc_verification_imk_udk(self):
        """Test KQ ARQC generation and verification using Issuer Master Key (IMK) with PAN and PSN (UDK derivation)."""
        gen_imk = self.hsm.process_raw_message(b"SSSSA00000U")
        imk_hex = gen_imk[8:8+33].decode("ascii")

        pan = "5413330089012345"
        psn = "00"
        atc_hex = "0001"
        txn_data_hex = "00000000100000000000000008400000000000084021081100123456"
        txn_len = len(txn_data_hex) // 2

        # Mode 1: Generate ARQC with IMK + PAN + PSN
        kq1_req = f"SSSSKQ1{imk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}".encode("ascii")
        kq1_resp = self.hsm.process_raw_message(kq1_req)
        self.assertTrue(kq1_resp.startswith(b"SSSSKR00"))
        arqc_hex = kq1_resp[8:].decode("ascii")
        self.assertEqual(len(arqc_hex), 16)

        # Mode 2: Verify ARQC with IMK + PAN + PSN
        kq2_req = f"SSSSKQ2{imk_hex}{pan};{psn}{atc_hex}{txn_len:04X}{txn_data_hex}{arqc_hex}".encode("ascii")
        kq2_resp = self.hsm.process_raw_message(kq2_req)
        self.assertEqual(kq2_resp, b"SSSSKR00")


class TestPyThalesHSMFacadeAndAsyncServer(unittest.TestCase):
    def test_pythales_hsm_standalone_execution(self):
        hsm = PyThalesHSM()
        req = b"\x00\x02NC"
        resp = hsm.execute_command(req)
        resp_len = struct.unpack("!H", resp[:2])[0]
        self.assertEqual(resp_len, len(resp) - 2)
        self.assertTrue(b"ND00" in resp)


    def test_pythales_hsm_server_start_stop(self):
        import time
        import socket

        hsm = PyThalesHSM(port=1598)
        hsm.start_server(host="127.0.0.1", port=1598, background=True)
        time.sleep(0.1)
        self.assertTrue(hsm.is_server_running())

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(("127.0.0.1", 1598))
            sock.sendall(b"\x00\x02NC")
            len_prefix = sock.recv(2)
            resp_len = struct.unpack("!H", len_prefix)[0]
            resp_data = sock.recv(resp_len)
            sock.close()

            self.assertTrue(resp_data.startswith(b"ND00"))
        finally:
            hsm.stop_server()
            time.sleep(0.1)
            self.assertFalse(hsm.is_server_running())


if __name__ == '__main__':
    unittest.main()






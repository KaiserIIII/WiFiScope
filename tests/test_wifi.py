import unittest

from wifiscope.wifi import decode_console, parse_netsh, parse_nmcli
from wifiscope.audit import assess


class WifiTests(unittest.TestCase):
    def test_netsh_multiple_bssids_hidden_and_chinese(self):
        text = '''SSID 1 : 实验室
    Authentication : WPA2-Personal
    Encryption : CCMP
    BSSID 1 : 02:00:00:00:00:01
         Signal : 71%
         Radio type : 802.11ax
         Channel : 36
    BSSID 2 : 02:00:00:00:00:02
         Signal : bad%
         Channel : nope
SSID 2 :
    身份验证 : 开放式
    加密 : 无
    BSSID 1 : 02:00:00:00:00:03
         信号 : 20%
         无线电类型 : 802.11n
         频道 : 6
'''
        rows = parse_netsh(text)
        self.assertEqual(rows, [
            dict(ssid='实验室', bssid='02:00:00:00:00:01', authentication='WPA2-Personal', encryption='CCMP', signal_percent=71, channel=36, radio_type='802.11ax'),
            dict(ssid='实验室', bssid='02:00:00:00:00:02', authentication='WPA2-Personal', encryption='CCMP', signal_percent=None, channel=None, radio_type=None),
            dict(ssid='', bssid='02:00:00:00:00:03', authentication='Open', encryption='None', signal_percent=20, channel=6, radio_type='802.11n'),
        ])

    def test_nmcli_escaped_fields_and_invalid_measurements(self):
        rows = parse_nmcli('Lab\\:West\\\\Wing:02\\:00\\:00\\:00\\:00\\:01:WPA2:80:36\n:02\\:00\\:00\\:00\\:00\\:02:--:101:-1\ntruncated')
        self.assertEqual(rows, [
            dict(ssid='Lab:West\\Wing', bssid='02:00:00:00:00:01', authentication='WPA2', encryption=None, signal_percent=80, channel=36, radio_type=None),
            dict(ssid='', bssid='02:00:00:00:00:02', authentication='Open', encryption=None, signal_percent=None, channel=None, radio_type=None),
        ])

    def test_decodes_utf8_and_gbk(self):
        self.assertEqual(decode_console('实验室'.encode('gbk')), '实验室')
        self.assertEqual(decode_console('实验室'.encode('utf-8')), '实验室')
        self.assertIsInstance(decode_console(b'\xff'), str)

    def test_empty_or_malformed_observations_are_not_invented(self):
        self.assertEqual(parse_netsh('Access denied: SECRET'), [])
        self.assertEqual(parse_netsh('SSID 1 : Lab\nBSSID 1 : invalid\nSignal : 200%'), [])
        self.assertEqual(parse_nmcli('junk'), [])

    def test_oversized_numeric_text_stays_unknown(self):
        text = 'Lab:02\\:00\\:00\\:00\\:00\\:01:WPA2:' + '9' * 5000 + ':36'
        self.assertIsNone(parse_nmcli(text)[0]['signal_percent'])

    def test_netsh_preserves_significant_ssid_whitespace(self):
        rows = parse_netsh('SSID 1 : Lab\nAuthentication : Open\nEncryption : None\nBSSID 1 : 02:00:00:00:00:01\nSSID 2 : Lab \nAuthentication : WPA2\nEncryption : CCMP\nBSSID 1 : 02:00:00:00:00:02\nSSID 3 :  Lab\t \nBSSID 1 : 02:00:00:00:00:03')
        self.assertEqual([row['ssid'] for row in rows], ['Lab', 'Lab ', ' Lab\t '])
        self.assertNotIn('mixed-security', {item['code'] for item in assess({'wifi': rows})})

    def test_nmcli_preserves_escaped_colon_backslash_and_ssid_spaces(self):
        rows = parse_nmcli(' Lab\\:West\\\\Wing :02\\:00\\:00\\:00\\:00\\:01:WPA2:70:36')
        self.assertEqual(rows[0]['ssid'], ' Lab:West\\Wing ')

import unittest

from wifiscope.audit import assess


class AuditTests(unittest.TestCase):
    def test_open_weak_signal_and_unknown_firewall(self):
        findings = assess({'wifi': [dict(ssid='Lab', bssid='02:00:00:00:00:01', authentication='Open', encryption='None', signal_percent=20)], 'firewall': [], 'gaps': []})
        codes = {x['code'] for x in findings}
        self.assertTrue({'open-wifi', 'weak-signal', 'firewall-unavailable'} <= codes)
        self.assertTrue(all(isinstance(x['evidence'], dict) for x in findings))

    def test_mixed_security_requires_verification(self):
        rows = [dict(ssid='Lab', bssid='02:00:00:00:00:01', authentication='WPA2-Personal', encryption='CCMP'), dict(ssid='Lab', bssid='02:00:00:00:00:02', authentication='Open', encryption='None')]
        findings = assess({'wifi': rows, 'firewall': [dict(name='Public', enabled=False)]})
        mixed = next(x for x in findings if x['code'] == 'mixed-security')
        self.assertIn('verify', mixed['recommendation'].lower())
        self.assertIn('firewall-disabled', {x['code'] for x in findings})
        self.assertNotIn('compromise', str(findings).lower())

    def test_wep_tkip_and_missing_security_are_distinct(self):
        findings = assess({'wifi': [dict(ssid='Legacy', encryption='WEP'), dict(ssid='Legacy2', authentication='WPA-Personal', encryption='TKIP'), dict(ssid='Unknown')], 'firewall': [dict(name='Public', enabled=None)]})
        codes = [x['code'] for x in findings]
        self.assertEqual(codes.count('weak-encryption'), 2)
        self.assertIn('security-unavailable', codes)
        self.assertNotIn('open-wifi', codes)
        self.assertNotIn('firewall-disabled', codes)

    def test_empty_and_hidden_networks_do_not_imply_security_or_same_identity(self):
        self.assertIn('wifi-unavailable', {x['code'] for x in assess({})})
        findings = assess({'wifi': [dict(ssid='', authentication='Open'), dict(ssid='', authentication='WPA2')], 'firewall': [dict(name='Public', enabled=True)]})
        self.assertNotIn('mixed-security', {x['code'] for x in findings})

    def test_partial_security_is_unknown_and_ssids_are_case_sensitive(self):
        rows = [dict(ssid='Lab', authentication='WPA2', encryption='CCMP'),
                dict(ssid='Lab', authentication='WPA2'),
                dict(ssid='lab', authentication='Open', encryption='None')]
        codes = {x['code'] for x in assess({'wifi': rows})}
        self.assertNotIn('mixed-security', codes)
        self.assertIn('security-unavailable', codes)

    def test_unknown_or_unsupported_security_is_unavailable_not_variation(self):
        for label in ('Unknown', 'Unsupported', 'N/A', '未知', 'unrecognized-future-method'):
            with self.subTest(label=label):
                report = {'wifi': [dict(ssid='Lab', authentication=label, encryption=label, signal_percent=70)], 'firewall': [dict(name='Public', enabled=True)]}
                findings = assess(report)
                self.assertEqual({item['code'] for item in findings}, {'security-unavailable'})
                self.assertIsNone(findings[0]['evidence']['authentication'])
                self.assertIsNone(findings[0]['evidence']['encryption'])
                report['wifi'].append(dict(ssid='Lab', authentication='WPA2', encryption='CCMP', signal_percent=70))
                self.assertNotIn('mixed-security', {item['code'] for item in assess(report)})

    def test_independent_open_or_weak_evidence_survives_unknown_other_field(self):
        report = {'wifi': [dict(ssid='Lab', authentication='Open', encryption='Unsupported'), dict(ssid='Other', authentication='Unknown', encryption='WEP')], 'firewall': [dict(name='Public', enabled=True)]}
        codes = [item['code'] for item in assess(report)]
        self.assertEqual(codes.count('security-unavailable'), 2)
        self.assertIn('open-wifi', codes)
        self.assertIn('weak-encryption', codes)

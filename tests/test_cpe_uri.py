"""Literal vectors for the reviewed, deliberately finite CPE URI profile."""
import unittest

from wifiscope.cpe_names import CPEName, parse_cpe
from wifiscope.cpe_uri import parse_cpe_uri, uri_to_formatted


class CPEURITests(unittest.TestCase):
    def test_uri_empty_fields_and_spelling(self):
        actual = uri_to_formatted('CPE:/A:Vendor:Product:1.0.0-RC.1')
        self.assertEqual(actual, 'cpe:2.3:a:Vendor:Product:1.0.0-RC.1:*:*:*:*:*:*:*')
        self.assertEqual(parse_cpe(actual).field('version').original_text, '1.0.0-RC.1')

    def test_packed_edition_and_literal_wildcards(self):
        self.assertEqual(
            uri_to_formatted('cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~'),
            'cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:*:*:*:online:win2003:x64:*')
        literal = parse_cpe(uri_to_formatted('cpe:/a:v:p:8.%2a:sp%3f'))
        pattern = parse_cpe(uri_to_formatted('cpe:/a:v:p:8.%02:sp%01'))
        self.assertEqual(literal.field('version').kind, 'literal')
        self.assertEqual(pattern.field('version').kind, 'pattern')
        self.assertEqual(literal.field('update').tokens, (('s', False), ('p', False), ('?', True)))
        self.assertEqual(pattern.field('update').tokens, (('s', False), ('p', False), ('?', False)))

    def test_all_eleven_slots_and_language_after_unpacking(self):
        actual = uri_to_formatted('cpe:/O:Acme:OS:3:-:~Suite~Pro~Linux~ARM64~Other:en-US')
        self.assertEqual(actual, 'cpe:2.3:o:Acme:OS:3:-:Suite:en-US:Pro:Linux:ARM64:Other')
        name = parse_cpe_uri('cpe:/O:Acme:OS:3:-:~Suite~Pro~Linux~ARM64~Other:en-US')
        self.assertIsInstance(name, CPEName)
        self.assertEqual(name, parse_cpe(actual))
        self.assertEqual(name.field('target_hw').original_text, 'ARM64')

    def test_omitted_empty_and_na_fields(self):
        vectors = (
            ('cpe:/', 'cpe:2.3:*:*:*:*:*:*:*:*:*:*:*'),
            ('cpe:/:v:p', 'cpe:2.3:*:v:p:*:*:*:*:*:*:*:*'),
            ('cpe:/h:v:p::::', 'cpe:2.3:h:v:p:*:*:*:*:*:*:*:*'),
            ('cpe:/a:-:-:-:-:-:-', 'cpe:2.3:a:-:-:-:-:-:-:*:*:*:*'),
            ('cpe:/a:v:p:::~-~-~-~-~-:-', 'cpe:2.3:a:v:p:*:*:-:-:-:-:-:-'),
        )
        for source, expected in vectors:
            with self.subTest(source=source):
                self.assertEqual(uri_to_formatted(source), expected)

    def test_punctuation_percent_decodes_once_and_preserves_quotes(self):
        source = 'cpe:/a:Ven%3aDor:pro%5cduct:RC%2502:%2A%3f:%7eSuite:en'
        formatted = r'cpe:2.3:a:Ven\:Dor:pro\\duct:RC\%02:\*\?:\~Suite:en:*:*:*:*'
        self.assertEqual(uri_to_formatted(source), formatted)
        name = parse_cpe_uri(source)
        self.assertEqual(name.field('version').kind, 'literal')
        self.assertEqual(name.field('version').original_text, 'RC%02')
        self.assertEqual(name.field('version').text, 'rc%02')
        self.assertEqual(name.field('version').tokens,
                         (('r', False), ('c', False), ('%', True), ('0', False), ('2', False)))
        self.assertEqual(name.field('edition').kind, 'literal')
        self.assertEqual(name.field('edition').original_text, '~Suite')
        self.assertEqual(name.attributes, parse_cpe(formatted).attributes)

    def test_every_listed_printable_percent_mapping(self):
        vectors = (
            ('21', '!'), ('22', '"'), ('23', '#'), ('24', '$'), ('25', '%'),
            ('26', '&'), ('27', "'"), ('28', '('), ('29', ')'), ('2a', '*'),
            ('2b', '+'), ('2c', ','), ('2f', '/'), ('3a', ':'), ('3b', ';'),
            ('3c', '<'), ('3d', '='), ('3e', '>'), ('3f', '?'), ('40', '@'),
            ('5b', '['), ('5c', '\\'), ('5d', ']'), ('5e', '^'), ('60', '`'),
            ('7b', '{'), ('7c', '|'), ('7d', '}'), ('7e', '~'),
        )
        for code, char in vectors:
            for hex_code in (code, code.upper()):
                with self.subTest(hex_code=hex_code):
                    name = parse_cpe_uri('cpe:/a:v:p:%' + hex_code)
                    self.assertEqual(name.field('version').kind, 'literal')
                    self.assertEqual(name.field('version').tokens, ((char, True),))
                    self.assertEqual(name.field('version').original_text, char)
                    self.assertEqual(uri_to_formatted('cpe:/a:v:p:%' + hex_code),
                                     'cpe:2.3:a:v:p:\\' + char + ':*:*:*:*:*:*:*')

    def test_raw_tilde_is_literal_except_leading_edition_marker(self):
        vectors = (
            ('cpe:/a:~v:p:x~y', r'cpe:2.3:a:\~v:p:x\~y:*:*:*:*:*:*:*'),
            ('cpe:/a:v:p:::e~d', r'cpe:2.3:a:v:p:*:*:e\~d:*:*:*:*:*'),
            ('cpe:/a:v:p:::~%7e~s%7e~t~h~o',
             r'cpe:2.3:a:v:p:*:*:\~:*:s\~:t:h:o'),
        )
        for source, expected in vectors:
            with self.subTest(source=source):
                self.assertEqual(uri_to_formatted(source), expected)

    def test_supported_pattern_edges_have_unquoted_wildcards(self):
        vectors = (
            ('%02RC%02', '*RC*', '*rc*'),
            ('%01%01RC%01', '??RC?', '??rc?'),
            ('%01RC%02', '?RC*', '?rc*'),
            ('%02%2a%02', r'*\**', '***'),
            ('%01-%01', '?-?', '?-?'),
        )
        for source, formatted, folded in vectors:
            with self.subTest(source=source):
                value = parse_cpe_uri('cpe:/a:v:p:' + source).field('version')
                self.assertEqual(value.kind, 'pattern')
                self.assertEqual(value.text, folded)
                self.assertEqual(uri_to_formatted('cpe:/a:v:p:' + source),
                                 'cpe:2.3:a:v:p:' + formatted + ':*:*:*:*:*:*:*')

    def test_preferred_language_forms(self):
        for language in ('en', 'ENG', 'en-US', 'zho-419', '-'):
            with self.subTest(language=language):
                self.assertEqual(parse_cpe_uri('cpe:/a:v:p::::' + language)
                                 .field('language').original_text, language)

    def test_rejects_malformed_and_unsupported_profile_with_controlled_error(self):
        bad = (
            None, 1, [], '', 'cpe:2.3:a:v:p', ' cpe:/a:v:p', 'cpe:/a:v:p ',
            'cpe:/x:v:p', 'cpe:/-:v:p', 'cpe:/aa:v:p', 'cpe:/%61:v:p',
            'cpe:/a:v:p:::::extra', 'cpe:/a:v:p:::~a~b~c~d',
            'cpe:/a:v:p:::~a~b~c~d~e~f', 'cpe:/a:v:p:::~',
            'cpe:/a:v:p:raw*', 'cpe:/a:v:p:raw?', 'cpe:/a:v:p:raw\\',
            'cpe:/a:v:p:raw!', 'cpe:/a:v:p:%', 'cpe:/a:v:p:%2',
            'cpe:/a:v:p:%xx', 'cpe:/a:v:p:%07', 'cpe:/a:v:p:%41',
            'cpe:/a:v:p:%20', 'cpe:/a:v:p:%2d', 'cpe:/a:v:p:%7f',
            'cpe:/a:v:p:%00', 'cpe:/a:v:p:%0a', 'cpe:/a:v:p:%ff',
            'cpe:/a:v:p:å', 'cpe:/a:v:p:\n', 'cpe:/a:v:p:\x7f',
            'cpe:/a:v:p:%02', 'cpe:/a:v:p:%01%01', 'cpe:/a:v:p:%02%01',
            'cpe:/a:v:p:a%02b', 'cpe:/a:v:p:a%01b', 'cpe:/a:v:p:%02%02a',
            'cpe:/a:v:p:a%02%02', 'cpe:/a:v:p:%01%02a', 'cpe:/a:v:p:a%02%01',
            'cpe:/a:v:p::::e', 'cpe:/a:v:p::::engl', 'cpe:/a:v:p::::en-1',
            'cpe:/a:v:p::::en-1234', 'cpe:/a:v:p::::en-USA',
            'cpe:/a:v:p::::en-US-x', 'cpe:/a:v:p::::en_US',
            'cpe:/a:v:p::::%02en',
            'cpe:/a:v:p:::~a~%02~c~d~e',
        )
        for source in bad:
            for convert in (parse_cpe_uri, uri_to_formatted):
                with self.subTest(source=source, convert=convert.__name__):
                    with self.assertRaisesRegex(ValueError, '^Invalid bounded CPE URI name\\.$'):
                        convert(source)

    def test_exact_decoded_field_limit(self):
        self.assertEqual(len(parse_cpe_uri('cpe:/a:' + 'a' * 1024)
                             .field('vendor').tokens), 1024)
        for source in ('cpe:/a:' + 'a' * 1025,
                       'cpe:/a:v:p:::~' + 'a' * 1025 + '~~~~'):
            with self.subTest(source_length=len(source)):
                with self.assertRaises(ValueError):
                    parse_cpe_uri(source)
        self.assertEqual(len(parse_cpe_uri('cpe:/a:' + '%21' * 1024)
                             .field('vendor').tokens), 1024)

    def test_exact_input_limit(self):
        source = 'cpe:/a:' + '%21' * 1024 + ':' + 'a' * 1016
        self.assertEqual(len(source), 4096)
        self.assertEqual(len(parse_cpe_uri(source).field('product').tokens), 1016)
        with self.assertRaises(ValueError):
            parse_cpe_uri(source + 'a')

    def test_exact_output_limit_and_escaping_expansion(self):
        source = 'cpe:/a:' + '~' * 1024 + ':' + '~' * 1010 + 'a'
        formatted = uri_to_formatted(source)
        self.assertEqual(len(formatted), 4096)
        self.assertEqual(len(parse_cpe(formatted).field('vendor').tokens), 1024)
        for convert in (uri_to_formatted, parse_cpe_uri):
            with self.subTest(convert=convert.__name__):
                with self.assertRaises(ValueError):
                    convert(source + 'a')


if __name__ == '__main__':
    unittest.main()

"""Validation, directional decisions, and charged CPE comparison work."""
from dataclasses import replace
import unittest

from wifiscope.cpe_names import Attribute, CPEName, compare_cpe, parse_cpe


def cpe(part='a', vendor='v', product='p', version='1', other='*'):
    return f'cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:{other}'


class CPEWorkTests(unittest.TestCase):
    def test_false_class_stops_attribute_work_after_full_validation(self):
        ticks = []
        result = compare_cpe(cpe(), cpe(part='o'), budget=lambda: ticks.append(1))
        self.assertEqual(result, 'false')
        self.assertEqual(len(ticks), 1)

    def test_false_literal_skips_later_pattern_work(self):
        ticks = []
        result = compare_cpe(cpe(vendor='different', product='*' + 'a' * 363),
                             cpe(product='a' * 363), budget=lambda: ticks.append(1))
        self.assertEqual(result, 'false')
        self.assertEqual(len(ticks), 2)

    def test_late_false_dominates_early_unknown_and_stops(self):
        ticks = []
        result = compare_cpe(cpe(vendor='v', product='different'),
                             cpe(vendor='*'), budget=lambda: ticks.append(1))
        self.assertEqual(result, 'false')
        self.assertEqual(len(ticks), 3)

    def test_invalid_late_attribute_refused_on_either_side_before_work(self):
        valid = Attribute('literal', 'x', (('x', False),), 'x')
        malformed = [
            object(), replace(valid, kind='invalid'),
            replace(valid, text=None), replace(valid, text='x' * 2049),
            replace(valid, tokens=[]), replace(valid, tokens=(('x', False),) * 1025),
            replace(valid, tokens=(['x', False],)), replace(valid, tokens=(('x',),)),
            replace(valid, tokens=((None, False),)), replace(valid, tokens=(('', False),)),
            replace(valid, tokens=(('xxxx', False),)), replace(valid, tokens=(('x', 0),)),
            replace(valid, original_text=1), replace(valid, original_text='x' * 1025),
        ]
        for side in ('source', 'target'):
            for attribute in malformed:
                with self.subTest(side=side, attribute=attribute):
                    source, target = parse_cpe(cpe()), parse_cpe(cpe(part='o'))
                    bad = source if side == 'source' else target
                    bad = CPEName(bad.attributes[:-1] + (attribute,))
                    if side == 'source':
                        source = bad
                    else:
                        target = bad
                    ticks = []
                    with self.assertRaisesRegex(ValueError, 'Invalid typed CPE attributes'):
                        compare_cpe(source, target, budget=lambda: ticks.append(1))
                    self.assertEqual(ticks, [])

    def test_invalid_attribute_container_and_cardinality_refused_before_work(self):
        attributes = parse_cpe(cpe()).attributes
        for container in (list(attributes), attributes[:-1], attributes + attributes[:1]):
            for side in ('source', 'target'):
                with self.subTest(side=side, container=container):
                    source, target = parse_cpe(cpe()), parse_cpe(cpe(part='o'))
                    if side == 'source':
                        source = CPEName(container)
                    else:
                        target = CPEName(container)
                    ticks = []
                    with self.assertRaisesRegex(ValueError, 'Invalid typed CPE attributes'):
                        compare_cpe(source, target, budget=lambda: ticks.append(1))
                    self.assertEqual(ticks, [])

    def test_string_and_typed_names_have_same_directional_decisions(self):
        for source, target, expected in [
                (cpe(), cpe(), 'true'),
                (cpe(), cpe(part='o'), 'false'),
                (cpe(version='1'), cpe(version='*'), 'unknown')]:
            for typed_source in (False, True):
                for typed_target in (False, True):
                    with self.subTest(source=source, target=target,
                                      typed_source=typed_source, typed_target=typed_target):
                        self.assertEqual(compare_cpe(
                            parse_cpe(source) if typed_source else source,
                            parse_cpe(target) if typed_target else target), expected)

    def test_invalid_name_and_formatted_input_categories_before_work(self):
        for invalid, category in [
                (None, 'requires typed formatted names'),
                ([], 'requires typed formatted names'),
                ({}, 'requires typed formatted names'),
                ('invalid', 'Invalid bounded CPE 2.3 formatted name'),
                (cpe(part='x'), 'Invalid bounded CPE part'),
                (cpe() + ':extra', 'Invalid bounded CPE 2.3 formatted name')]:
            for side in ('source', 'target'):
                with self.subTest(invalid=invalid, side=side):
                    ticks = []
                    with self.assertRaisesRegex(ValueError, category):
                        compare_cpe(invalid if side == 'source' else cpe(),
                                    invalid if side == 'target' else cpe(part='o'),
                                    budget=lambda: ticks.append(1))
                    self.assertEqual(ticks, [])

    def test_three_valued_pattern_any_na_and_quoted_relations(self):
        for source, target, expected in [
                ('*', 'ab*', 'unknown'), ('*', 'a*b', 'unknown'),
                ('*', '-', 'true'), ('-', '-', 'true'), ('-', 'x', 'false'),
                (r'\-', '-', 'false'), (r'\*', r'\*', 'true'),
                (r'\*', '*', 'unknown'), (r'app\*', 'appx', 'false'),
                ('app*', 'appx', 'true'), ('ab?', 'ab', 'true'),
                ('ab?', 'abc', 'true'), ('ab?', 'abcd', 'false'),
                ('a*b', 'acb', 'unknown'), ('ab', 'a*b', 'unknown'),
                ('ab', 'ab*', 'unknown'), ('a*b', 'a*b', 'unknown')]:
            with self.subTest(source=source, target=target):
                self.assertEqual(compare_cpe(cpe(product=source), cpe(product=target)), expected)

    def test_typed_validation_retains_existing_rich_field_limits_and_semantics(self):
        name = parse_cpe(cpe())
        for attribute in [
                Attribute('literal', 'x' * 2048, (('xxx', True),) * 1024, 'x' * 1024),
                Attribute('literal', '', (), None),
                Attribute('literal', '*', (('*', False),), None)]:
            with self.subTest(attribute=attribute):
                typed = CPEName(name.attributes[:-1] + (attribute,))
                self.assertEqual(compare_cpe(typed, typed), 'true')

    def test_callback_cancellation_and_failure_propagate_during_pattern_work(self):
        for error in (InterruptedError('cancelled'), RuntimeError('failure'),
                      ValueError('callback failed'), OverflowError('callback overflow')):
            with self.subTest(error=type(error).__name__):
                ticks = []

                def charge():
                    ticks.append(1)
                    if len(ticks) == 5:
                        raise error

                with self.assertRaises(type(error)) as caught:
                    compare_cpe(cpe(product='*app*'), cpe(product='myapplication'), budget=charge)
                self.assertIs(caught.exception, error)
                self.assertEqual(len(ticks), 5)

    def test_standalone_pattern_bound_and_explicit_budget_work(self):
        source, target = cpe(product='*' + 'a' * 363), cpe(product='a' * 363)
        self.assertEqual(compare_cpe(source, target), 'unknown')
        ticks = []
        self.assertEqual(compare_cpe(source, target, budget=lambda: ticks.append(1)), 'true')
        self.assertGreater(len(ticks), 131072)
        self.assertEqual(compare_cpe(cpe(product='*' + 'a' * 360),
                                     cpe(product='a' * 360)), 'true')


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_datacleaner
----------------------------------

Tests for `datacleaner` module.
"""

import pprint
import unittest

from datacleaner.datacleaner import (
    split_name,
    split_email,
    clean_url,
    username_from_first_last_name,
    IPSplitter)


class TestPrinter(object):
    def __init__(self, print_level=-1):
        self.error_msgs = []
        self.normal_msgs = []
        self.verbose_msgs = []
        self.debug_msgs = []
        self.print_level = print_level

    def error(self, msg):
        self.error_msgs.append(msg)
        if self.print_level >= 0:
            print "ERROR  : " + msg

    def normal(self, msg):
        self.normal_msgs.append(msg)
        if self.print_level >= 1:
            print "NORMAL : " + msg

    def verbose(self, msg):
        self.verbose_msgs.append(msg)
        if self.print_level >= 2:
            print "VERBOSE: " + msg

    def debug(self, msg):
        self.debug_msgs.append(msg)
        if self.print_level >= 3:
            print "DEBUG  : " + msg

    def pprint_debug(self, obj):
        msg = pprint.pformat(obj, indent=4)
        self.debug(msg)


class SplitNameTests(unittest.TestCase):

    def test_split_name_simple(self):
        title, first_name, last_name = split_name('Joe Bloggs')
        self.assertEqual(title, '')
        self.assertEqual(first_name, 'Joe')
        self.assertEqual(last_name, 'Bloggs')

    def test_split_name_three_parts(self):
        title, first_name, last_name = split_name('Joe P. Bloggs')
        self.assertEqual(title, '')
        self.assertEqual(first_name, 'Joe P.')
        self.assertEqual(last_name, 'Bloggs')

    def test_split_name_simple_title(self):
        title, first_name, last_name = split_name('Ms Jo Bloggs')
        self.assertEqual(title, 'Ms')
        self.assertEqual(first_name, 'Jo')
        self.assertEqual(last_name, 'Bloggs')

    def test_split_name_simple_title_with_dot(self):
        title, first_name, last_name = split_name('Dr. Jo Bloggs')
        self.assertEqual(title, 'Dr')
        self.assertEqual(first_name, 'Jo')
        self.assertEqual(last_name, 'Bloggs')


class UsernameFirstnameLastnameTests(unittest.TestCase):

    def test_username_from_first_last_name_simple(self):
        username = username_from_first_last_name('Joe', 'Bloggs')
        self.assertEqual(username, 'joe_bloggs')

    def test_username_from_first_last_name_is_all_lower(self):
        username = username_from_first_last_name('Joe', 'BLOGGS')
        self.assertEqual(username, 'joe_bloggs')

    def test_username_from_first_last_name_ignores_non_alphanum(self):
        username = username_from_first_last_name('Joe!', '?BLOGGS?')
        self.assertEqual(username, 'joe_bloggs')

    def test_username_from_first_last_name_ignores_non_ascii(self):
        username = username_from_first_last_name('Joe!', u'£Blø→oggs?')
        self.assertEqual(username, 'joe_bloggs')


class CleanUrlTests(unittest.TestCase):
    BASE_URL = 'www.domain.org'
    GOOD_URL = 'http://' + BASE_URL

    def test_clean_url_leaves_good_url_alone(self):
        self.assertEqual(self.GOOD_URL, clean_url(self.GOOD_URL))

    def test_clean_url_strips_whitespace(self):
        self.assertEqual(self.GOOD_URL, clean_url(' ' + self.GOOD_URL + '\t'))

    def test_clean_url_adds_http_if_missing(self):
        self.assertEqual(self.GOOD_URL, clean_url(self.BASE_URL))

    def test_clean_url_doesnt_add_http_to_empty_string(self):
        self.assertEqual('', clean_url(' '))

    def test_clean_url_leaves_https_alone(self):
        https_url = 'https://' + self.BASE_URL
        self.assertEqual(https_url, clean_url(https_url))


class SplitEmailTests(unittest.TestCase):
    EMAIL1 = 'test@domain.org'
    EMAIL2 = 'test2@domain.org'
    EMAIL_LIST = [EMAIL1, EMAIL2]

    def setUp(self):
        self.printer = TestPrinter()

    def split_email(self, email_str):
        return split_email(email_str, self.printer)

    def test_single_email_address_is_not_changed(self):
        self.assertEqual([self.EMAIL1], self.split_email(self.EMAIL1))

    def test_email_addresses_split_by_semicolon(self):
        email_str = ' ; '.join(self.EMAIL_LIST)
        self.assertEqual(self.EMAIL_LIST, self.split_email(email_str))

    def test_email_addresses_split_by_forward_slash(self):
        email_str = '/'.join(self.EMAIL_LIST)
        self.assertEqual(self.EMAIL_LIST, self.split_email(email_str))

    def test_email_addresses_split_by_commas(self):
        email_str = ', '.join(self.EMAIL_LIST)
        self.assertEqual(self.EMAIL_LIST, self.split_email(email_str))

    def test_email_addresses_split_by_or(self):
        email_str = ' or '.join(self.EMAIL_LIST)
        self.assertEqual(self.EMAIL_LIST, self.split_email(email_str))
        email_str = ' OR '.join(self.EMAIL_LIST)
        self.assertEqual(self.EMAIL_LIST, self.split_email(email_str))

    def test_blank_email_string_doesnt_cause_error(self):
        self.assertEqual([], self.split_email(''))

    def test_invalid_email_string_doesnt_cause_error(self):
        self.assertEqual([], self.split_email('test2@'))
        self.assertEqual([], self.split_email('@domain.org'))
        self.assertEqual([], self.split_email('test2.domain.org'))

    def test_double_dots_are_eliminated(self):
        email_str = 'test@domain..org'
        self.assertEqual([self.EMAIL1], self.split_email(email_str))

    def test_quoted_emails_are_unquoted(self):
        email_str = "'" + self.EMAIL1 + "'"
        self.assertEqual([self.EMAIL1], self.split_email(email_str))

    def test_trailing_dots_are_removed(self):
        email_str = self.EMAIL1 + "."
        self.assertEqual([self.EMAIL1], self.split_email(email_str))

    def test_no_dot_com_becomes_dot_com(self):
        email_str = 'test@gmailcom'
        self.assertEqual(['test@gmail.com'], self.split_email(email_str))

    def test_comma_in_email_becomes_dot(self):
        email_str = 'test@domain,org'
        self.assertEqual([self.EMAIL1], self.split_email(email_str))


class SplitIPAddressRangeTests(unittest.TestCase):

    def setUp(self):
        self.printer = TestPrinter()
        self.splitter = IPSplitter(self.printer)

    def split_ip(self, ip_str):
        return self.splitter.split_ip_address_range(ip_str)

    def test_no_ip_address(self):
        ip = ' '
        self.assertEqual([], self.split_ip(ip))

    def test_no_ip_address_but_extraneous_text(self):
        ip = 'applied for username and password'
        self.assertEqual([], self.split_ip(ip))
        ip = '*applied for username and password*'
        self.assertEqual([], self.split_ip(ip))
        ip = '"applied for username and password"'
        self.assertEqual([], self.split_ip(ip))
        ip = 's/n'
        self.assertEqual([], self.split_ip(ip))

    def test_single_ip_address(self):
        ip = '44.45.46.47'
        self.assertEqual([[ip, None]], self.split_ip(ip))

    def test_two_ip_addresses_separated_by_semicolon(self):
        ip1 = '44.45.46.48'
        ip2 = '55.56.57.55'
        ip_str = '; '.join((ip1, ip2))
        self.assertEqual([[ip1, None], [ip2, None]], self.split_ip(ip_str))

    def test_two_ip_addresses_separated_by_space(self):
        ip1 = '44.45.46.48'
        ip2 = '55.56.57.55'
        ip_str = ' '.join((ip1, ip2))
        self.assertEqual([[ip1, None], [ip2, None]], self.split_ip(ip_str))

    def test_two_ip_addresses_separated_by_newline(self):
        ip1 = '44.45.46.48'
        ip2 = '55.56.57.55'
        ip_str = '\n '.join((ip1, ip2))
        self.assertEqual([[ip1, None], [ip2, None]], self.split_ip(ip_str))

    def test_two_ip_addresses_separated_by_and(self):
        ip1 = '44.45.46.48'
        ip2 = '55.56.57.55'
        ip_str = ' and '.join((ip1, ip2))
        self.assertEqual([[ip1, None], [ip2, None]], self.split_ip(ip_str))

    def test_range_of_two_full_ip_addresses(self):
        ip1 = '44.45.46.48'
        ip2 = '44.45.46.55'
        ip_str = ' - '.join((ip1, ip2))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))
        ip_str = '-'.join((ip1, ip2))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))
        ip_str = ' .. '.join((ip1, ip2))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))
        ip_str = ' to '.join((ip1, ip2))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))
        ip_str = ' TO '.join((ip1, ip2))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))

    def test_range_of_two_full_ip_addresses_with_trailing_dot(self):
        ip1 = '44.45.46.48'
        ip2 = '44.45.46.55'
        ip_str = ' - '.join((ip1, ip2)) + '.'
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))

    def test_range_of_full_ip_address_and_single_octet(self):
        ip1 = '44.45.46.48'
        ip2 = '44.45.46.55'
        ip2_frag = ip2.split('.')[-1]  # = '58'
        ip_str = ' - '.join((ip1, ip2_frag))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))
        ip_str = '-'.join((ip1, ip2_frag))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))
        ip_str = ' .. '.join((ip1, ip2_frag))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))
        ip_str = ' to '.join((ip1, ip2_frag))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))
        ip_str = ' TO '.join((ip1, ip2_frag))
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_str))

    def test_cidr_range(self):
        ip1 = '44.45.46.128'
        ip2 = '44.45.46.191'
        ip_cidr = ip1 + '/26'
        self.assertEqual([[ip1, ip2]], self.split_ip(ip_cidr))

    def test_string_with_netmask(self):
        ip_str = 'ip: 193.168.182.192\nnetmask: 255.255.255.0\ngateway: 193.168.182.1'
        self.assertEqual([
            ['193.168.182.192', None],
            ['193.168.182.1', None],
        ], self.split_ip(ip_str))

    def test_local_addresses_excluded(self):
        ip_str = 'ip: 192.168.182.192\nanother: 10.11.12.13'
        self.assertEqual([], self.split_ip(ip_str))

    def test_ip_glob_star(self):
        ip1 = '44.45.46.*'
        ip2 = '44.45.*.*'
        self.assertEqual([['44.45.46.0', '44.45.46.255']], self.split_ip(ip1))
        self.assertEqual([['44.45.0.0', '44.45.255.255']], self.split_ip(ip2))

    def test_ip_glob_range_in_third_octet(self):
        ip1 = '44.45.46-48.*'
        self.assertEqual([['44.45.46.0', '44.45.48.255']], self.split_ip(ip1))

    def test_real_data(self):
        ip_data = "41.209.14.169/29, 41.209.14.170,41.209.14.172 and 41.209.14.173. "
        expected = [
            ['41.209.14.168', '41.209.14.175'],
            ['41.209.14.170', None],
            ['41.209.14.172', None],
            ['41.209.14.173', None]
        ]
        self.assertEqual(expected, self.split_ip(ip_data))


if __name__ == '__main__':
    unittest.main()

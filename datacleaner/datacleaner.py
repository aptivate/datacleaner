# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

import re
import pprint
from netaddr import (IPAddress, IPNetwork, IPRange, IPGlob, AddrFormatError)

from django.core.validators import validate_email
from django.core.exceptions import ValidationError

TITLE_CHOICES = ('mr', 'mrs', 'miss', 'ms', 'dr', 'prof')


def split_name(name):
    title = first_name = last_name = ''
    name_parts = name.split()
    if name_parts[0].lower().strip('.') in TITLE_CHOICES:
        title = name_parts[0].strip('.')
        name_parts = name_parts[1:]
    last_name = name_parts[-1]
    first_name = ' '.join(name_parts[:-1])
    return title, first_name, last_name

USERNAME_CHARS_RE = re.compile(r'[^a-z0-9_]')


def username_from_first_last_name(first_name, last_name):
    username = first_name + '_' + last_name
    username = USERNAME_CHARS_RE.sub(r'', username.lower())
    # max length of username is 30
    return username[:30]


def clean_url(url):
    # remove whitespace
    url = url.strip()
    # add http:// to the front if left off and string has contents
    if url and not url.startswith('http'):
        url = 'http://' + url
    return url

comma_re = re.compile(r'[,]')
question_re = re.compile(r'[,?]')
paren_quote_re = re.compile(r'[ ()|\']')
doubledot_re = re.compile(r'\.\.')
notcom_re = re.compile(r'([^.])com$')


def split_email(email_str, printer):
    email_str = email_str.lower().strip()
    num_at_chars = email_str.count('@')
    if num_at_chars == 0:
        printer.verbose('Did not find any "@" chars in: %s' % email_str)
        return []
    printer.debug('Got "%s" with %d @ chars' % (email_str, num_at_chars))
    if ';' in email_str:
        # split on ;
        # strip whitespace
        # replace , with .
        email_list = [comma_re.sub(r'.', e.strip()) for e in email_str.split(';')]
    elif '/' in email_str:
        # split on /
        # strip whitespace
        # replace , with .
        email_list = [comma_re.sub(r'.', e.strip()) for e in email_str.split('/')]
    elif ',' in email_str and num_at_chars > 1:
        # split on ,
        # strip whitespace
        email_list = [e.strip() for e in email_str.split(',')]
    elif ' or ' in email_str:
        # split on ' or '
        # strip whitespace
        # replace , with .
        email_list = [comma_re.sub(r'.', e.strip()) for e in email_str.split(' or ')]
    elif ' ' in email_str and num_at_chars > 1:
        # could just remove spaces as typos, or split??  Data suggests remove ...
        # split on whitespace
        # strip whitespace
        email_list = [e.strip() for e in email_str.split()]
    elif num_at_chars == 1:
        # single item list
        # strip whitespace
        # replace , with .
        email_list = [comma_re.sub(r'.', email_str.strip())]
    else:
        printer.verbose(
                'Found %d "@" chars but could not find way to split: %s' %
                (num_at_chars, email_str))
        return []

    cleaned_email_list = []
    for email in email_list:
        # turn stray commas or ? into .
        email = question_re.sub(r'.', email)
        # remove stray spaces or ()
        email = paren_quote_re.sub(r'', email)
        # if there is a double dot, get rid of it
        email = doubledot_re.sub(r'.', email)
        # strip trailing .
        email = email.strip('.').strip('/')
        # if they forgot the . before com at the end
        email = notcom_re.sub(r'\1.com', email)
        # if there is anything left, add it to list
        if email:
            cleaned_email_list.append(email)

    # sanity checks
    if num_at_chars != len(cleaned_email_list):
        printer.verbose('Probable mistake in split_email(): found %d "@" chars but %d email addresses'
                % (num_at_chars, len(cleaned_email_list)))
        printer.verbose('String was "%s" - emails found were ["%s"]' %
            (email_str, '", "'.join(cleaned_email_list)))

    # only return valid email addresses
    valid_email_list = []
    for email in cleaned_email_list:
        try:
            validate_email(email)
            valid_email_list.append(email)
        except ValidationError:
            printer.verbose('Could not validate email: %s' % email)
    return valid_email_list


# ipv4_re copied from django.core.validators, but I have removed the ^ and $
ipv4_re = re.compile('(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}')
ip_fragment_re = re.compile(r'[.0-9]+')
digit_re = re.compile(r'\d+')
cidr_re = re.compile(r'/(\d+)')
non_whitespace_re = re.compile(r'\S+')
whitespace_re = re.compile(r'\s+')
dotdot_re = re.compile(r'\.\.')
to_re = re.compile(r'to', re.IGNORECASE)
ip_glob_re = re.compile('''
        (25[0-5]|2[0-4]\d|[0-1]?\d?\d)\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)\.   # the first 2 digits
        (                                                                  # followed by one of:
        \d{1,3}\.\d{1,3} \s* (-|to|TO|\.\.) \s* \d{1,3}                    # "12.23-28"  "12.23 to 28" etc
        (?![.0-9])                                     # but only when not followed by . or digit - other could be 12.3.4.5-12.3.4.6
        |
        \d{1,3}\.\*                                                        # 12.*   23.* etc
        |
        \*\.\*                                                             # *.*
        |
        \d{1,3} \s* (-|to|TO) \s* \d{1,3} \.\*                             # 23-28.*  12.23 to 28.*
        )''',
        re.VERBOSE)


def len_ip_range(ip_range):
    return (ip_range.last - ip_range.first) + 1


def remove_whitespace(string):
    return whitespace_re.sub('', string)


class IPSplitter(object):
    def __init__(self, printer):
        self.printer = printer

    def report_undealt_with(self):
        self.printer.normal(u'Could not deal with string: "%s"' % self.ip_str)
        self.hit_error = True

    def add_ip_range_to_list(self, ip_range):
        self.ip_range_list.append(ip_range)

    def add_ip_address_str_to_list(self, ip_address_str):
        try:
            ip_net = IPNetwork(ip_address_str)
        except AddrFormatError as e:
            self.printer.error(str(e))
            self.report_undealt_with()
        else:
            self.add_ip_range_to_list(ip_net)

    def add_cidr_str_to_list(self, cidr_str):
        self.add_ip_address_str_to_list(cidr_str)

    def add_ip_address_range_str_to_list(self, ip_start_str, ip_end_str):
        try:
            ip_net = IPRange(ip_start_str, ip_end_str)
        except AddrFormatError as e:
            self.printer.error(str(e))
            self.report_undealt_with()
        else:
            self.add_ip_range_to_list(ip_net)

    def add_ip_glob_str_to_list(self, ip_glob_str):
        try:
            ip_net = IPGlob(ip_glob_str)
        except AddrFormatError as e:
            self.printer.error(str(e))
            self.report_undealt_with()
        else:
            self.add_ip_range_to_list(ip_net)

    def convert_net_to_first_last_strings(self, net):
        ip_start = IPAddress(net.first)
        # check if local or if netmask
        if ip_start.is_private():
            self.printer.verbose('skipping local IP: %s' % str(ip_start))
            return None
        if ip_start.is_netmask():
            self.printer.normal('skipping netmask IP: %s' % str(ip_start))
            return None
        if not ip_start.is_unicast():
            self.printer.normal('skipping multicast IP: %s' % str(ip_start))
            return None
        if net.first == net.last:
            return [str(ip_start), None]
        else:
            ip_end = str(IPAddress(net.last))
            return [str(ip_start), ip_end]

    def collapse_ip_list(self):
        ip_string_range_list = []
        for net in self.ip_range_list:
            first_last = self.convert_net_to_first_last_strings(net)
            if first_last:
                ip_string_range_list.append(first_last)
        return ip_string_range_list

    def deal_with_single_address(self, ip_start, post_ip_match):
        self.printer.debug('Looks like this is a single IP address, not a range.')
        # assume it is start of new range
        # add single ip address and continue to next loop
        self.add_ip_address_str_to_list(ip_start)

    def deal_with_range(self, ip_start, post_ip_match):
        # must be range
        self.printer.debug('Looks like this is a range.')
        ip_fragment_match = ip_fragment_re.search(self.ip_str, self.index)
        if not ip_fragment_match:
            self.printer.verbose('Not a range!  Treating as a single IP')
            self.add_ip_address_str_to_list(ip_start)
            return
        self.index = ip_fragment_match.end()
        ip_fragment = ip_fragment_match.group(0).strip('.')
        if ipv4_re.match(ip_fragment):
            self.printer.debug('IP range end fragment is a full IP address: %s' % ip_fragment)
            self.add_ip_address_range_str_to_list(ip_start, ip_fragment)
        else:
            self.printer.error('"%s" slipped past the glob check!' % self.ip_str)
            self.printer.debug('IP range end fragment is NOT a full IP address: %s' % ip_fragment)
            ip_fragment_numbers = ip_fragment.split('.')
            ip_start_numbers = ip_start.split('.')
            if len(ip_fragment_numbers) >= 2:
                self.printer.normal('Found end of range with too many fragments')
                self.report_undealt_with()
                return
            # go backwards through range
            for i in range(len(ip_fragment_numbers)):
                index = -1 - i
                ip_start_numbers[index] = ip_fragment_numbers[index]
            ip_end = '.'.join(ip_start_numbers)
            self.printer.debug('Constructed IP range end: %s' % ip_end)
            self.add_ip_address_range_str_to_list(ip_start, ip_end)

    def deal_with_cidr(self, ip_start, post_ip_match):
        # must be CIDR
        self.printer.debug('Looks like this is a CIDR.')
        self.index = post_ip_match.start()
        cidr_match = cidr_re.search(self.ip_str, self.index)
        if not cidr_match:
            self.printer.verbose('Not a CIDR!  Treating as a single IP')
            self.report_undealt_with()
            self.add_ip_address_str_to_list(ip_start)
            return
        cidr_num = int(cidr_match.group(1))
        self.index = cidr_match.end()
        if cidr_num > 32 or cidr_num < 16:
            self.printer.verbose('CIDR is out of range: %d - treating as a single IP' % cidr_num)
            self.report_undealt_with()
            self.add_ip_address_str_to_list(ip_start)
            return
        # now actually make it into a CIDR
        self.add_cidr_str_to_list(ip_start + cidr_match.group(0))

    def deal_with_glob(self, match_glob):
        ip_glob = match_glob.group(0)
        ip_glob = remove_whitespace(ip_glob)
        ip_glob = dotdot_re.sub('-', ip_glob)
        ip_glob = to_re.sub('-', ip_glob)
        self.printer.debug('Found glob "%s"' % ip_glob)
        self.add_ip_glob_str_to_list(ip_glob)

    def find_first_match(self):
        """ returns (match, is_glob) """
        start_ipv4 = start_glob = 9999999
        match_ipv4 = ipv4_re.search(self.ip_str, self.index)
        match_glob = ip_glob_re.search(self.ip_str, self.index)
        if not match_ipv4 and not match_glob:
            return None, False
        if match_ipv4:
            start_ipv4 = match_ipv4.start()
        if match_glob:
            start_glob = match_glob.start()
        if start_ipv4 < start_glob:
            return match_ipv4, False
        else:
            return match_glob, True

    def split_ip_address_range(self, ip_str):
        self.ip_str = ip_str.lower().strip()
        self.printer.debug('Searching for IPs in: "%s"' % self.ip_str)
        self.ip_range_list = []
        self.index = 0
        self.hit_error = False
        while self.index < len(self.ip_str):
            self.printer.debug('self.index is now %d, remaining string is "%s"' %
                    (self.index, self.ip_str[self.index:]))
            # here we are looking for the start of a range or a glob
            match, is_glob = self.find_first_match()
            if not match:
                self.printer.debug('No more IP addresses to be found.')
                break
            self.index = match.end()
            if is_glob:
                self.deal_with_glob(match)
                continue
            ip_start = match.group(0)
            self.printer.debug('Found start IP address: %s' % ip_start)
            post_ip_match = non_whitespace_re.search(self.ip_str, self.index)
            if not post_ip_match:
                self.printer.debug('Reached end of non-whitespace.')
                self.add_ip_address_str_to_list(ip_start)
                break
            self.index = post_ip_match.start()
            next_non_whitespace = post_ip_match.group(0)
            self.printer.debug('Next non whitespace is: %s' % next_non_whitespace)
            if (next_non_whitespace[0].isdigit() or
                    next_non_whitespace[0:3] == 'and' or
                    next_non_whitespace[0] == ',' or
                    next_non_whitespace[0] == ';'):
                self.deal_with_single_address(ip_start, post_ip_match)
            elif (next_non_whitespace[0] == '-' or
                    next_non_whitespace[0:2] == 'to'):
                # must be range
                self.deal_with_range(ip_start, post_ip_match)
            elif next_non_whitespace[0:2] == '..':
                # must be range - but need to skip the dots
                self.index += 2
                self.deal_with_range(ip_start, post_ip_match)
            elif next_non_whitespace[0] == '/':
                # must be CIDR
                self.printer.debug('Looks like this is a CIDR.')
                self.deal_with_cidr(ip_start, post_ip_match)
            else:
                # interesting ...
                self.printer.verbose('Unexpected non whitespace, skipping: "%s"' % next_non_whitespace)
                # assume that this is a separator and it is a single IP address
                self.deal_with_single_address(ip_start, post_ip_match)

        ip_range_list = self.collapse_ip_list()
        if self.hit_error:
            self.printer.verbose("Found ranges:\n %s" % pprint.pformat(ip_range_list, indent=4))
        else:
            self.printer.debug("Found ranges:")
            self.printer.pprint_debug(ip_range_list)
        return ip_range_list

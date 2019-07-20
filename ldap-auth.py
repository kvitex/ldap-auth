#!/usr/bin/env python3
import ldap
import yaml
import sys
import re


if __name__ == "__main__":
    if len(sys.argv) > 3:
        config_file_name = sys.argv[1]
        user_name = sys.argv[2]
        user_password = sys.argv[3]
    else:
        print('Too few arguments. Usage: ad-ldap-auth.py <config_file> <username> <password>')
        exit(-1)
    if (user_password == "") or (user_name == ""):
        print('Reject')
        exit(-1)
    try:
        with open(config_file_name) as config_file:
            cfg = yaml.load(config_file.read())
    except FileNotFoundError or FileExistsError as Error:
        print('Can not open configuration file {}'.format(config_file_name))
        print(Error)
        exit(-1)
    except yaml.scanner.ScannerError as Error:
        print('Error while parsing configuration file {}'.format(config_file_name))
        print(Error)
        exit(-1)
    except Exception as Error:
        print(Error)
        exit(-1)
    ad = ldap.initialize(cfg['ldap_url'])
    try:
      ad.simple_bind_s(user_name, user_password)
    except ldap.LDAPError as e:
        print(e)
        exit(-1)
    ad.unbind_s()
    ad = ldap.initialize(cfg['ldap_url'])
    try:
      ad.simple_bind_s(cfg['ldap_user'], cfg['ldap_user_password'])
    except ldap.LDAPError as e:
        print(e)
        exit(-1)
    ad.set_option(ldap.OPT_REFERRALS, 0)
    try:
      results = ad.search_s(cfg['basedn'], ldap.SCOPE_SUBTREE,
                '(sAMAccountName={})'.format(user_name.split('@')[0]),)
    except ldap.LDAPError as e:
        print(e)
        exit(-1)
    if re.search('={}'.format(cfg['group']), str(results[0][1].get('memberOf', ''))) is None:
        print('Reject')
        exit(1)
    else:
        print('Accept')
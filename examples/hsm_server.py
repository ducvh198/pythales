#!/usr/bin/env python

import getopt
import os
import sys

from pythales.hsm import HSM

def show_help(name):
    """
    Show help and basic usage
    """
    print('Usage: python3 {} [OPTIONS]... '.format(name))
    print('Thales HSM command simulator')
    print('  -p, --port=[PORT]\t\tTCP port to listen, 1500 by default')
    print('  -k, --key=[KEY]\t\tTCP port to listen, 1500 by default')
    print('  -h, --header=[HEADER]\t\tmessage header, empty by default')
    print('  -d, --debug\t\t\tEnable debug mode (show CVV/PVV mismatch etc)')
    print('  -s, --skip-parity\t\t\tSkip key parity checks')
    print('  -a, --approve-all\t\t\tApprove all requests')


def is_env_true(primary, secondary=None):
    val = os.environ.get(primary)
    if val is None and secondary:
        val = os.environ.get(secondary)
    if val is not None:
        return val.lower() in ('1', 'true', 'yes', 'on')
    return False


if __name__ == '__main__':
    port = None
    env_port = os.environ.get('HSM_PORT') or os.environ.get('PORT')
    if env_port:
        try:
            port = int(env_port)
        except ValueError:
            print('Invalid TCP port: {}'.format(env_port))
            sys.exit(1)

    header = os.environ.get('HSM_HEADER', os.environ.get('HEADER', ''))
    key = os.environ.get('HSM_KEY', os.environ.get('KEY', None))
    debug = is_env_true('HSM_DEBUG', 'DEBUG')
    skip_parity = True if is_env_true('HSM_SKIP_PARITY', 'SKIP_PARITY') else None
    approve_all = True if is_env_true('HSM_APPROVE_ALL', 'APPROVE_ALL') else None

    optlist, args = getopt.getopt(sys.argv[1:], 'h:p:k:dsa', ['header=', 'port=', 'key=', 'debug', 'skip-parity', 'approve-all', 'help'])
    for opt, arg in optlist:
        if opt in ('-h', '--header'):
            header = arg
        elif opt in ('-p', '--port'):
            try:
                port = int(arg)
            except ValueError:
                print('Invalid TCP port: {}'.format(arg))
                sys.exit(1)
        elif opt in ('-k', '--key'):
            key = arg
        elif opt in ('-d', '--debug'):
            debug = True
        elif opt in ('-s', '--skip-parity'):
            skip_parity = True
        elif opt in ('-a', '--approve-all'):
            approve_all = True
        elif opt in ('--help',):
            show_help(sys.argv[0])
            sys.exit(0)

    hsm = HSM(port=port, header=header, key=key, debug=debug, skip_parity=skip_parity, approve_all=approve_all)
    hsm.run()


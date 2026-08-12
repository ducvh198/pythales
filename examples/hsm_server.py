#!/usr/bin/env python

import getopt
import os
import sys

from pythales.hsm import PyThalesHSM

def show_help(name):
    """
    Show help and basic usage
    """
    print('Usage: python3 {} [OPTIONS]... '.format(name))
    print('Thales HSM command simulator')
    print('  -p, --port=[PORT]\t\tTCP port to listen, 1500 by default')
    print('  -k, --key=[KEY]\t\t32-hex character LMK string')
    print('  -h, --header=[HEADER]\t\tmessage header, empty by default')
    print('  -d, --debug\t\t\tEnable debug mode (show CVV/PVV mismatch etc)')
    print('  -s, --skip-parity\t\t\tSkip key parity checks')
    print('  -a, --approve-all\t\t\tApprove all requests')
    print('  --max-connections=[NUM]\tMax concurrent connections (default: 1000)')
    print('  --idle-timeout=[SEC]\t\tIdle connection timeout in seconds (default: 30.0)')
    print('  --disable-keepalive\t\tDisable TCP Keep-Alive')


def is_env_true(primary, secondary=None, default=False):
    val = os.environ.get(primary)
    if val is None and secondary:
        val = os.environ.get(secondary)
    if val is not None:
        return val.lower() in ('1', 'true', 'yes', 'on')
    return default


if __name__ == '__main__':
    port = None
    env_port = os.environ.get('HSM_PORT') or os.environ.get('PORT')
    if env_port:
        try:
            port = int(env_port)
        except ValueError:
            print('Invalid TCP port: {}'.format(env_port))
            sys.exit(1)

    host = os.environ.get('HSM_HOST', os.environ.get('HOST', '0.0.0.0'))
    header = os.environ.get('HSM_HEADER', os.environ.get('HEADER', ''))
    key = os.environ.get('HSM_KEY', os.environ.get('KEY', None))
    debug = is_env_true('HSM_DEBUG', 'DEBUG')
    skip_parity = True if is_env_true('HSM_SKIP_PARITY', 'SKIP_PARITY') else None
    approve_all = True if is_env_true('HSM_APPROVE_ALL', 'APPROVE_ALL') else None

    # Connection management defaults
    max_connections = 1000
    env_max_conn = os.environ.get('HSM_MAX_CONNECTIONS') or os.environ.get('MAX_CONNECTIONS')
    if env_max_conn:
        try:
            max_connections = int(env_max_conn)
        except ValueError:
            print('Invalid HSM_MAX_CONNECTIONS: {}'.format(env_max_conn))
            sys.exit(1)

    idle_timeout = 30.0
    env_idle_timeout = os.environ.get('HSM_IDLE_TIMEOUT') or os.environ.get('IDLE_TIMEOUT')
    if env_idle_timeout:
        try:
            idle_timeout = float(env_idle_timeout)
        except ValueError:
            print('Invalid HSM_IDLE_TIMEOUT: {}'.format(env_idle_timeout))
            sys.exit(1)

    enable_keepalive = is_env_true('HSM_ENABLE_KEEPALIVE', 'ENABLE_KEEPALIVE', default=True)

    optlist, args = getopt.getopt(
        sys.argv[1:],
        'h:p:k:dsa',
        [
            'header=',
            'port=',
            'key=',
            'debug',
            'skip-parity',
            'approve-all',
            'max-connections=',
            'idle-timeout=',
            'disable-keepalive',
            'enable-keepalive',
            'help',
        ],
    )
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
        elif opt in ('--max-connections',):
            try:
                max_connections = int(arg)
            except ValueError:
                print('Invalid max-connections: {}'.format(arg))
                sys.exit(1)
        elif opt in ('--idle-timeout',):
            try:
                idle_timeout = float(arg)
            except ValueError:
                print('Invalid idle-timeout: {}'.format(arg))
                sys.exit(1)
        elif opt in ('--disable-keepalive',):
            enable_keepalive = False
        elif opt in ('--enable-keepalive',):
            enable_keepalive = True
        elif opt in ('--help',):
            show_help(sys.argv[0])
            sys.exit(0)

    hsm = PyThalesHSM(
        port=port,
        header=header,
        key=key,
        debug=debug,
        skip_parity=skip_parity,
        approve_all=approve_all,
    )
    print(
        f"Starting PyThales AsyncHSMServer (max_connections={max_connections}, idle_timeout={idle_timeout}s, keepalive={enable_keepalive})..."
    )
    try:
        hsm.start_server(
            host=host,
            port=port,
            max_connections=max_connections,
            idle_timeout=idle_timeout,
            enable_keepalive=enable_keepalive,
            background=False,
        )
    except OSError as e:
        print(f"Error starting server on {host}:{port if port else 1500}: {e}")
        print("Please check if another process is already listening on this port.")
        sys.exit(1)




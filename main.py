#!/usr/bin/python3
from configparser import ConfigParser
from logging import getLogger, INFO, basicConfig
from time import sleep, time

import libs.shodan_check as shodan


def main():
    """Doing the thing."""
    # Setting logging.
    log = getLogger('shodan_report.log')
    basicConfig(
            format='%(asctime)s %(name)s %(levelname)s: %(message)s',
            datefmt='%m/%d/%Y %H:%M:%S',
            level=INFO,
            filename='shodan_report.log'
        )
    # Setting configuration.
    config = ConfigParser()
    config.read('config.cnf')
    mail_info = {
        'sender': config['mail']['sender'],
        'recipients': config['mail']['rcpts'],
        'server': config['mail']['server'],
        'body': str()
    }
    api_key = config['shodan']['api']
    # Getting IP addresses.
    ip_list = []
    ip_file = 'ip_addrs.ignore'
    _file = open(ip_file, 'r', encoding='ascii')
    for line in _file:
        ip_list.append(line.strip('\n'))
    _file.close()
    # Running Shodan search.
    log.info('Beginning Shodan search.')
    start = time()
    shodan_results = []
    for ip_addr in set(ip_list):
        log.debug('Searching Shodan for %s.', ip_addr)
        sleep(2)
        test_info = shodan.shodan_search(ip_addr, api_key)
        shodan_results.append(test_info)
        log.debug('Shodan search for %s complete.', ip_addr)
    # Mailing results.
    end = time()
    elapsed = end - start
    log.info('Shodan search complete in %f seconds', elapsed)
    for entry in shodan_results:
        if len(entry) > 0:
            mail_info['body'] += str(entry) + '\n\n'
    shodan.mail_send(mail_info)


if __name__ == '__main__':
    main()

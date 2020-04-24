# Created by GitHub user: 24nmcnamara.
# Last modified by GitHub user: gbentley.
# Last modified date: 04/23/2020
# Licensed under GPLv3
from requests import get, HTTPError, Timeout, ConnectionError
from logging import getLogger
from smtplib import SMTP, SMTPConnectError
from email.mime.text import MIMEText

from socket import gethostbyname, gaierror


def shodan_search(ip_addr, api_key):
    """Searhces Shodan for info, returns a dictionary.
    This fucntion searches Shodan for informatoin related to a given
    IP address and returns the results in a dictionary format.

    Keyword Arguments:
    ip_addr - str(), The IP address used in the Shodan query.
    api_key - str(), the API key for Shodan.

    Outputs:
    shodan_results - dict ()

    Raises:
    ConnectionError - Occurs when a connection related error
    (e.g., DNS resolution) occurs.
    HTTPError - Occurs when the server returns a non-200 HTTP response.
    Timeout - Occcurs when a timeout occur (3 seconds)."""
    # Setting up logging.
    log = getLogger('shodan_report.log')
    # Setting some variables.
    shodan_results = {}
    url = (
        'https://api.shodan.io/shodan/host/' + ip_addr + '?key=' + api_key
    )
    try:
        response = get(url, timeout=5)
        response.raise_for_status()
    except ConnectionError:
        log.exception(
            'A general, connection related error occurred.'
        )
    except Timeout:
        log.exception(
            'A timeout occurred when making the request to Shodan.'
        )
    except HTTPError:
        log.exception(
            'A HTTP error occurred while retrieving data from Shodan.'
            )
    if response.status_code == 200:
        log.info('Successfully retrieved info for %s from Shodan.', ip_addr)
        data = response.json()
        shodan_results = {
            'ip': ip_addr,
            'timestamps': [],
            'ports': data.get('ports'),
            'hostnames': []
        }
        for entry in data.get('data'):
            shodan_results['timestamps'].append(
                {'port': entry['port'],
                 'timestamp': entry['timestamp']}
            )
            shodan_results['hostnames'].append(entry['hostnames'])
    return shodan_results


def mail_send(mail_info):
    """Takes input, sends mail.
    Keyword arguments:
    mail_info - A dict() object with the following keys and
    corresponding values: sender, recipients, server and body.
    Outputs:
    Sends an email, returns nothing.
    Raises:
    gaierror - Occurs when DNS resolution of a hostname fails.
    SMTPConnectError - Occurs when the remote SMTP sever refuses the
    connection."""
    # Setting logging.
    log = getLogger('shodan_report.log')
    # Defining mail properties.
    msg = MIMEText(mail_info['body'])
    msg['Subject'] = 'Shodan Report'
    msg['From'] = mail_info['sender']
    msg['To'] = mail_info['recipients']
    # Obtaining IP address of SMTP server host name.  If using an IP
    # address, omit the gethostbyname function.
    try:
        s = SMTP(gethostbyname(mail_info['server']), '25')
    except gaierror:
        log.exception(
            'Hostname resolution of %s failed.' % mail_info['server']
        )
        exit(1)
    except SMTPConnectError:
        log.exception('Unable to connect to %s, the server refused the ' +
                      'connection.' % mail_info['server'])
        exit(1)
    # Sending the mail.
    s.sendmail(mail_info['sender'], mail_info['recipients'], msg.as_string())

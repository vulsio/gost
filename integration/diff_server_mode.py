import argparse
from typing import Tuple
from deepdiff import DeepDiff
import requests
import pprint
from concurrent.futures import ThreadPoolExecutor
import logging


def diff_response(args: Tuple[str, str]):
    try:
        response_old = requests.get(
            'http://127.0.0.1:1325/'+args[0]+'/cves/'+args[1]).json()
        response_new = requests.get(
            'http://127.0.0.1:1326/'+args[0]+'/cves/'+args[1]).json()
    except Exception as e:
        logging.error(f'Failed to GET request..., err: {e}')
        raise

    diff = DeepDiff(response_old, response_new, ignore_order=True)
    if diff != {}:
        logging.warning(
            f'There is a difference between old and new:\n {pprint.pformat({args[1]: diff}, indent=2)}')


parser = argparse.ArgumentParser()
parser.add_argument('ostype', choices=['debian', 'redhat', 'microsoft'],
                    help='Specify the OS to be started in server mode when testing.')
parser.add_argument('--cveid_list_path',
                    help='A file path containing a line by line list of CVE-IDs to be diffed in server mode results')
parser.add_argument('--debug', action=argparse.BooleanOptionalAction, help='print debug message')
args = parser.parse_args()

log_level = logging.INFO
if args.debug:
    log_level = logging.DEBUG
logging.basicConfig(encoding='utf-8', level=log_level)
logging.info(f'Start {args.ostype} Diff server mode results')

cveid_path = None
if args.cveid_list_path != None:
    cveid_path = args.cveid_list_path
else:
    cveid_path = 'integration/cveid_' + args.ostype + '.txt'

logging.debug(f'Use CVE-ID List Path: {cveid_path}')

with open(cveid_path) as f:
    cveids = [s.strip() for s in f.readlines()]
    with ThreadPoolExecutor() as executor:
        ins = ((args.ostype, cveid) for cveid in cveids)
        executor.map(diff_response, ins)

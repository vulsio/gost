import argparse
import logging
from typing import Tuple
from deepdiff import DeepDiff
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import pprint
from concurrent.futures import ThreadPoolExecutor
import os
import random
import math
import json
import shutil
import time
import uuid


def diff_cveid(ostype: str, cveid: str):
    session = requests.Session()
    retries = Retry(total=5,
                    backoff_factor=1,
                    status_forcelist=[503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))

    # Endpoint
    # /redhat/cves/:id
    # /debian/cves/:id
    # /ubuntu/cves/:id
    # /microsoft/cves/:id
    path = f'{ostype}/cves/{cveid}'
    try:
        response_old = session.get(
            f'http://127.0.0.1:1325/{path}', timeout=2).json()
        response_new = session.get(
            f'http://127.0.0.1:1326/{path}', timeout=2).json()
    except requests.exceptions.ConnectionError as e:
        logger.error(
            f'Failed to Connection..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
        raise
    except requests.exceptions.ReadTimeout as e:
        logger.warning(
            f'Failed to Read Response..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
        raise
    except Exception as e:
        logger.error(
            f'Failed to GET request..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
        raise

    diff = DeepDiff(response_old, response_new, ignore_order=True)
    if diff != {}:
        logger.warning(
            f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({"mode": "cveid", "args": args, "path": path}, indent=2)}')

        diff_path = f'integration/diff/{ostype}/cveid/{cveid}'
        with open(f'{diff_path}.old', 'w') as w:
            w.write(json.dumps(response_old, indent=4))
        with open(f'{diff_path}.new', 'w') as w:
            w.write(json.dumps(response_new, indent=4))


def diff_cveids(ostype: str, cveids: list[str]):
    session = requests.Session()
    retries = Retry(total=5,
                    backoff_factor=1,
                    status_forcelist=[503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))

    # Endpoint
    # POST /redhat/multi-cves
    # POST /microsoft/multi-cves
    path = f'{ostype}/multi-cves'
    k = math.ceil(len(cveids)/5)
    for _ in range(5):
        payload = {"cveIDs": random.sample(cveids, k)}
        try:
            response_old = session.post(
                f'http://127.0.0.1:1325/{path}', data=json.dumps(payload), headers={'content-type': 'application/json'}, timeout=2).json()
            response_new = session.post(
                f'http://127.0.0.1:1326/{path}', data=json.dumps(payload), headers={'content-type': 'application/json'}, timeout=2).json()
        except requests.exceptions.ConnectionError as e:
            logger.error(
                f'Failed to Connection..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
            raise
        except requests.exceptions.ReadTimeout as e:
            logger.warning(
                f'Failed to Read Response..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
            raise
        except Exception as e:
            logger.error(
                f'Failed to GET request..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
            raise

        diff = DeepDiff(response_old, response_new, ignore_order=True)
        if diff != {}:
            logger.warning(
                f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({"mode": "cveid", "args": args, "path": path}, indent=2)}')

            title = uuid.uuid4()
            diff_path = f'integration/diff/{ostype}/cveids/{title}'
            with open(f'{diff_path}.old', 'w') as w:
                w.write(json.dumps(
                    {'args': args, 'response': response_old}, indent=4))
            with open(f'{diff_path}.new', 'w') as w:
                w.write(json.dumps(
                    {'args': args, 'response': response_new}, indent=4))


def diff_package(ostype: str, package: str):
    session = requests.Session()
    retries = Retry(total=5,
                    backoff_factor=1,
                    status_forcelist=[503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))

    # Endpoint
    # /redhat/:release/pkgs/:name/unfixed-cves
    # /debian/:release/pkgs/:name/unfixed-cves
    # /debian/:release/pkgs/:name/fixed-cves
    # /ubuntu/:release/pkgs/:name/unfixed-cves
    # /ubuntu/:release/pkgs/:name/fixed-cves

    # ([releases], ['unfixed-cves', 'fixed-cves'])
    os_specific_urls: Tuple[list, list]
    if ostype == 'debian':
        os_specific_urls = (['9', '10'], [
                            'unfixed-cves', 'fixed-cves'])
    elif ostype == 'ubuntu':
        os_specific_urls = (['1404', '1604', '1804', '2004', '2010', '2104'], [
                            'unfixed-cves', 'fixed-cves'])
    elif ostype == 'redhat':
        os_specific_urls = (['3', '4', '5', '6', '7', '8'], ['unfixed-cves'])
    else:
        logger.error(
            f'Failed to diff_response..., err: This OS type({ostype}) does not support test mode(package)')
        raise NotImplementedError

    for rel in os_specific_urls[0]:
        for fix_status in os_specific_urls[1]:
            path = f'{ostype}/{rel}/pkgs/{package}/{fix_status}'
            os.makedirs(
                f'integration/diff/{ostype}/package/{rel}({fix_status})', exist_ok=True)
            try:
                response_old = session.get(
                    f'http://127.0.0.1:1325/{path}', timeout=(2.0, 30.0)).json()
                response_new = session.get(
                    f'http://127.0.0.1:1326/{path}', timeout=(2.0, 30.0)).json()
            except requests.exceptions.ConnectionError as e:
                logger.error(
                    f'Failed to Connection..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
                raise
            except requests.exceptions.ReadTimeout as e:
                logger.warning(
                    f'Failed to Read Response..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
                raise
            except Exception as e:
                logger.error(
                    f'Failed to GET request..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
                raise

            diff = DeepDiff(response_old, response_new, ignore_order=True)
            if diff != {}:
                logger.warning(
                    f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({"mode": "package", "args": args, "path": path}, indent=2)}')

                diff_path = f'integration/diff/{ostype}/package/{rel}({fix_status})/{package}'
                with open(f'{diff_path}.old', 'w') as w:
                    w.write(json.dumps(response_old, indent=4))
                with open(f'{diff_path}.new', 'w') as w:
                    w.write(json.dumps(response_new, indent=4))


def diff_response(args: Tuple[str, str, list[str]]):
    try:
        if args[0] == 'cveid':
            diff_cveid(args[1], args[2][0])
        if args[0] == 'cveids':
            diff_cveids(args[1], args[2])
        if args[0] == 'package':
            diff_package(args[1], args[2][0])
    except Exception:
        exit(1)


parser = argparse.ArgumentParser()
parser.add_argument('mode', choices=['cveid', 'cveids', 'package'],
                    help='Specify the mode to test.')
parser.add_argument('ostype', choices=['debian', 'ubuntu', 'redhat', 'microsoft'],
                    help='Specify the OS to be started in server mode when testing.')
parser.add_argument('--list_path',
                    help='A file path containing a line by line list of CVE-IDs or Packages to be diffed in server mode results')
parser.add_argument("--sample_rate", type=float, default=0.01,
                    help="Adjust the rate of data used for testing (len(test_data) * sample_rate)")
parser.add_argument(
    '--debug', action=argparse.BooleanOptionalAction, help='print debug message')
args = parser.parse_args()

logger = logging.getLogger(__name__)
stream_handler = logging.StreamHandler()

if args.debug:
    logger.setLevel(logging.DEBUG)
    stream_handler.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
    stream_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    '%(levelname)s[%(asctime)s] %(message)s', "%m-%d|%H:%M:%S")
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

logger.info(f'start {args.ostype} server mode test(mode: {args.mode})')

logger.info('check the communication with the server')
for i in range(5):
    try:
        if requests.get('http://127.0.0.1:1325/health').status_code == requests.codes.ok and requests.get('http://127.0.0.1:1326/health').status_code == requests.codes.ok:
            logger.info('communication with the server has been confirmed')
            break
    except Exception:
        pass
    time.sleep(1)
else:
    logger.error('Failed to communicate with server')
    exit(1)

list_path = None
if args.list_path != None:
    list_path = args.list_path
else:
    if args.mode in ['cveid', 'cveids']:
        list_path = 'integration/cveid/cveid_' + args.ostype + '.txt'
    if args.mode == 'package':
        list_path = 'integration/package/package_' + args.ostype + '.txt'

if list_path == None:
    logger.error(
        f'Failed to set list path..., list_path: {list_path}, args.list_path: {args.list_path}')
    exit(1)

if not os.path.isfile(list_path):
    logger.error(f'Failed to find list path..., list_path: {list_path}')
    exit(1)

logger.debug(
    f'Test Mode: {args.mode}, OStype: {args.ostype}, Use List Path: {list_path}')

diff_path = f'integration/diff/{args.ostype}/{args.mode}'
if os.path.exists(diff_path):
    shutil.rmtree(diff_path)
os.makedirs(diff_path, exist_ok=True)

with open(list_path) as f:
    list = [s.strip() for s in f.readlines()]
    list = random.sample(list, math.ceil(len(list) * args.sample_rate))
    if args.mode == 'cveids':
        diff_response((args.mode, args.ostype, list))
    else:
        with ThreadPoolExecutor() as executor:
            ins = ((args.mode, args.ostype, [e]) for e in list)
            executor.map(diff_response, ins)

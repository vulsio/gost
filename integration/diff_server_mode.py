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
import json


def convert_redis_only_none(response, os):
    if os == "redhat":
        if response["Details"] == None:
            response["Details"] = []
        if response["References"] == None:
            response["References"] = []
    elif os == "ubuntu":
        if response["references"] == None:
            response["references"] = []
        if response["notes"] == None:
            response["notes"] = []
        if response["bugs"] == None:
            response["bugs"] = []

    return response


def diff_cveid(args: Tuple[str, bool, str]):
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
    try:
        response_old = session.get(
            f'http://127.0.0.1:1325/{args[0]}/cves/{args[2]}', timeout=(2.0, 30.0)).json()
        response_new = session.get(
            f'http://127.0.0.1:1326/{args[0]}/cves/{args[2]}', timeout=(2.0, 30.0)).json()
        if args[1]:
            response_new = convert_redis_only_none(response_new, args[0])
    except requests.exceptions.ConnectionError as e:
        logger.error(f'Failed to Connection..., err: {e}')
        raise
    except requests.exceptions.ReadTimeout as e:
        logger.error(
            f'Failed to Read Response..., err: {e}, args: {args}')
        raise
    except Exception as e:
        logger.error(f'Failed to GET request..., err: {e}')
        raise

    diff = DeepDiff(response_old, response_new, ignore_order=True)
    if diff != {}:
        logger.warning(
            f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({"mode": "cveid", "args": args, "diff": diff}, indent=2)}')


def diff_package(args: Tuple[str, bool, str]):
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
    if args[0] == 'debian':
        os_specific_urls = (['9', '10'], [
                            'unfixed-cves', 'fixed-cves'])
    elif args[0] == 'ubuntu':
        os_specific_urls = (['1404', '1604', '1804', '2004', '2010', '2104'], [
                            'unfixed-cves', 'fixed-cves'])
    elif args[0] == 'redhat':
        os_specific_urls = (['3', '4', '5', '6', '7', '8'], ['unfixed-cves'])
    else:
        logger.error(
            f'Failed to diff_response..., err: This OS type({args[1]}) does not support test mode(package)')
        raise NotImplementedError

    for rel in os_specific_urls[0]:
        for fix_status in os_specific_urls[1]:
            try:
                response_old = session.get(
                    f'http://127.0.0.1:1325/{args[0]}/{rel}/pkgs/{args[2]}/{fix_status}', timeout=(2.0, 30.0)).json()
                response_new = session.get(
                    f'http://127.0.0.1:1326/{args[0]}/{rel}/pkgs/{args[2]}/{fix_status}', timeout=(2.0, 30.0)).json()
                if args[1]:
                    response_new = convert_redis_only_none(
                        response_new, args[0])
            except requests.exceptions.ConnectionError as e:
                logger.error(f'Failed to Connection..., err: {e}')
                raise
            except requests.exceptions.ReadTimeout as e:
                logger.error(
                    f'Failed to Read Response..., err: {e}, args: {args}')
                raise
            except Exception as e:
                logger.error(f'Failed to GET request..., err: {e}')
                raise

            diff = DeepDiff(response_old, response_new, ignore_order=True)
            if diff != {}:
                logger.warning(
                    f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({"mode": "package", "args": args, "diff": diff}, indent=2)}')


def diff_response(args: Tuple[str, str, bool, str]):
    try:
        if args[0] == 'cveid':
            diff_cveid((args[1], args[2], args[3]))
        if args[0] == 'package':
            diff_package((args[1], args[2], args[3]))
    except Exception:
        exit(1)


parser = argparse.ArgumentParser()
parser.add_argument('mode', choices=['cveid', 'package'],
                    help='Specify the mode to test.')
parser.add_argument('ostype', choices=['debian', 'ubuntu', 'redhat', 'microsoft'],
                    help='Specify the OS to be started in server mode when testing.')
parser.add_argument('--list_path',
                    help='A file path containing a line by line list of CVE-IDs or Packages to be diffed in server mode results')
parser.add_argument('--diff_rdb_redis', action='store_true',
                    help='Diff the output of RDB and Redis.')
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

list_path = None
if args.list_path != None:
    list_path = args.list_path
else:
    if args.mode == 'cveid':
        list_path = 'integration/cveid_' + args.ostype + '.txt'
    if args.mode == 'package':
        list_path = 'integration/package_' + args.ostype + '.txt'

if list_path == None:
    logger.error(
        f'Failed to set list path..., list_path: {list_path}, args.list_path: {args.list_path}')
    exit(1)

if not os.path.isfile(list_path):
    logger.error(f'Failed to find list path..., list_path: {list_path}')
    exit(1)

logger.debug(
    f'Test Mode: {args.mode}, OStype: {args.ostype}, Use List Path: {list_path}, Diff_RDB_Redis: {args.diff_rdb_redis}')

with open(list_path) as f:
    list = [s.strip() for s in f.readlines()]
    with ThreadPoolExecutor() as executor:
        ins = ((args.mode, args.ostype, args.diff_rdb_redis, e) for e in list)
        executor.map(diff_response, ins)

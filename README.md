# Log4j Bypass

This script enables you to easily test for all of the Log4J bypass methods. You can just test for the original bypass by not adding any tags or you can add the --bypass tag to test for the bypasses.

# MANUAL:
```
usage: bypass.py [-h] [-u URL] [-p PROXY] [-l USEDLIST]
                 [--request-type REQUEST_TYPE] [--headers-file HEADERS_FILE]
                 [--run-all-tests] [--exclude-user-agent-fuzzing]
                 [--wait-time WAIT_TIME] [--bypass]
                 [--dns-callback-provider DNS_CALLBACK_PROVIDER]
                 [--custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Check a single URL.
  -p PROXY, --proxy PROXY
                        send requests through proxy
  -l USEDLIST, --list USEDLIST
                        Check a list of URLs. - default urls.txt
  --request-type REQUEST_TYPE
                        Request Type: (get, post) - [Default: get].
  --headers-file HEADERS_FILE
                        Headers fuzzing list - [default: headers.txt].
  --run-all-tests       Run all available tests on each URL.
  --exclude-user-agent-fuzzing
                        Exclude User-Agent header from fuzzing - useful to
                        bypass weak checks on User-Agents.
  --wait-time WAIT_TIME
                        Wait time after all URLs are processed (in seconds) -
                        [Default: 60].
  --bypass              Extend scans with bypass payloads.
  --dns-callback-provider DNS_CALLBACK_PROVIDER
                        DNS Callback provider (Options: dnslog.cn,
                        interact.sh) - [Default: interact.sh].
  --custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST
                        Custom DNS Callback Host.
```

# INSTALLATION AND FIRST USE
To use this, you may want to set up a CanaryToken to save the DNS hit results and have them as a cleaner interface. To do so, go to https://canarytokens.org/generate#, select the Log4Shell token, and put the generated token into the program after the optional ``` --custom-dns-callback-host ``` tag when executing the script. You can also use other services such as http://dnslog.cn or your own hosted server setup through a utility such as marshalsec (https://github.com/mbechler/marshalsec), OpenLDAP, or similar resources. If you want to host your own server for this, check out the free TryHackMe room created by John Hammond that walks you through setting up the servers to exploit log4j at https://tryhackme.com/room/solar.

```
# You must have git and python3 installed to use this code
git clone 
cd log4j-bypass
chmod 777 bypass.py
python3 bypass.py -h
```

Email me at cyberqueenmeg@wearehackerone with any questions and feel free to fork this repo for your own use or contribute! I'll do my best to keep it updated with new bypasses but I might miss one so please contribute if you find a new bypass :D

# CREDITS
Special thanks to https://github.com/fullhunt/log4j-scan for inspiring the majority of this code! This is a fork of their project modified to include more details and make it easier to test all the bypasses and new versions.

Thank you to all of the defenders who are actively trying to find and patch this vulnerability and who are sharing information and fixes that they have found.

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
```
# You must have git and python3 installed to use this code
git clone 
cd log4j-bypass
chmod 777 bypass.py
python3 bypass.py
```

Email me at cyberqueenmeg@wearehackerone with any questions and feel free to fork this repo for your own use or contribute! I'll do my best to keep it updated with new bypasses but I might miss one so please contribute if you find a new bypass :D

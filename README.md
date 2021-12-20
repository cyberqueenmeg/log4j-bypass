# Log4j Bypass
This script enables you to easily test for all of the Log4J bypass methods. 

# HACKERS WITH HALOS
This script was created for ETHICAL usage only. Ethical uses include testing your own software, testing software in a penetration test, testing software in a bug bounty, testing purposefully vulnerable software either independently or in an educational setting, or testing software with consent by the creator. Be Hackers with Halos and only use this for ethical purposes. I am not liable for any damage you cause with this software and you are encouraged to look at the source code to understand how it works before using it. You are not permitted to use this software for illegal or cyberwarfare purposes.

# MANUAL:
```
usage: python3 bypass.py [-h] [-u URL] [-p PROXY] [-l USEDLIST]
                 [--request-type REQUEST_TYPE] [--headers-file HEADERS_FILE]
                 [--wait-time WAIT_TIME]
                 [--callback-url CUSTOM_DNS_CALLBACK_HOST]

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
  --wait-time WAIT_TIME
                        Wait time after all URLs are processed (in seconds) -
                        [Default: 60].
  --callback-url CUSTOM_DNS_CALLBACK_HOST
                        Custom DNS Callback Host.

```

# INSTALLATION AND FIRST USE
To use this, you may want to set up a CanaryToken to save the DNS hit results and have them as a cleaner interface. To do so, go to https://canarytokens.org/generate#, select the Log4Shell token, and put the generated token into the program after the optional ``` --custom-dns-callback-host ``` tag when executing the script. You can also use other services such as http://dnslog.cn or your own hosted server setup through a utility such as marshalsec (https://github.com/mbechler/marshalsec), OpenLDAP, or similar resources. If you want to host your own server for this, check out the free TryHackMe room created by John Hammond that walks you through setting up the servers to exploit log4j at https://tryhackme.com/room/solar.

```
# You must have git and python3 installed to use this code
git clone https://github.com/cyberqueen-meg/log4j-bypass.git
cd log4j-bypass
chmod 777 bypass.py
python3 bypass.py -h
```

Email me at cyberqueenmeg@wearehackerone with any questions and feel free to fork this repo for your own use or contribute! I'll do my best to keep it updated with new bypasses but I might miss one so please contribute if you find a new bypass :D

# CREDITS
Special thanks to https://github.com/fullhunt/log4j-scan for inspiring the majority of this code! This is a fork of their project modified to include more details and make it easier to test all the bypasses and new versions.

Special thanks to https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words for providing lots of the bypasses I included in the bypass_payloads array

Thank you to all of the defenders who are actively trying to find and patch this vulnerability and who are sharing information and fixes that they have found.

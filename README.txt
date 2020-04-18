__      _______  _   _  _____ _          _ _ 
\ \    / /  __ \| \ | |/ ____| |        | | |
 \ \  / /| |__) |  \| | (___ | |__   ___| | |
  \ \/ / |  ___/| . ` |\___ \| '_ \ / _ \ | |
   \  /  | |    | |\  |____) | | | |  __/ | |
    \/   |_|    |_| \_|_____/|_| |_|\___|_|_|                         (Version 1.0)
    
              56 50 4E 53 68 65 6C 6C
                                     
  
  
  
VPNShell - Exploiting known SSL VPN 0 day vulnerabilities to pwn shell from it. Since may be 2018, 
Orange Tsai has found many vulnerabilities from over 3 popular SSL VPN services which tottaly impressive.
After I saw his blog about that vulnerabilies, I found that SSL VPN (portal) is really dangerous and 
exploitable. I found over 2 RCE from bug bounty programs and just feel cool with that. I realized that
all of that vulnerabilities are new, about 1 or 2 years ago, which mean it's will hard to know and fix it.
So, I decided to create the best SSL VPN exploit tool for everyone when most of exploits I found are really bad.
Also, most of the bugs will lead to RCE, so I try to get shell from those 0day bugs. Although there are some bugs
(Pulse SSL VPN) require the user interaction, so I may change the name of the tool in the future. But until
now, VPNShell still just only support 1 vulnerability in Palo Alto SSL VPN, I will update it day-by-day.


Usage:
 Scan for VPN service:         python[3] -s [HOST] -n [-OPTIONS]
 Exploit VPN 0day:             python[3] -s [HOST] -e [CVE] [-OPTIONS]
 Show list of 0day:            python[3] -l [-OPTIONS]
 
 Example:
  - python[3] vpnsh.py -s site.co -n
  - python[3] vpnsh.py -s vpn.site.co -e CVE-2019-1579
  - python[3] vpnsh.py -l
  - python[3] vpnsh.py -s 745.123.5.88 -e CVE-2019-1579 -c id -p 8081
  
  
  
(?) Does VPNShell work with Python2?
Yes, VPNShell is support both python2 and python3.

(?) Does VPNShell work in Windows?
VPNShell works with both Windows and Unix, it will give the best
experience for each OS.

(?) Does VPNShell is the best SSL VPN exploitation tool?
Yeah, I bringing the best experience for the hackers with the best 
exploit code that both reduce False Posotive and False Negative and 
give hackers the best shell interface with the best exploitation analyst. 
And if there is any issue, I will fix it and even update the code.

(?) How much vulnerabilies does VPNShell support?
Well, until now just 1: CVE-2019-1579. But, in the future, there will
be 5 or 7 or even more. I will update it.
  
  
  
 Author: @shelldev (working at HackerOne and BugCrowd

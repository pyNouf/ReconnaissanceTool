import whois
import sys 
import socket  # Socket programming is a way of connecting two nodes on a network to communicate with each other
import dns.resolver #DNS toolkit for Python. It can be used dynamic updates, nameserver testing for queries, zone transfers and many other things
import nmap #Python library which helps in using nmap port scanner. It allows to easily manipulate nmap scan results automatize scanning task
import re
import ssl
import requests #Requests is an Apache2 Licensed HTTP library, written in Python.
import builtwith
from colorama import Fore, init
from pyfiglet import figlet_format  # special format
from datetime import datetime as dt  # Time and Data

#Varibles
my_resolver = dns.resolver.Resolver()
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
port_min = 0
port_max = 65535
scanner = nmap.PortScanner()
Error = '\033[91m'
Succses = '\033[92m'
init(autoreset=True)

# Special format for tool name using pyfiglet
print(figlet_format("RECO") ,"Reconnaissance Tool")



# Functions
def ip_command_list():
    return ("""\n
--------------------------------------------------
Please enter the type of IP Scan you want to run:
--------------------------------------------------
Δ To TCP Scan Well Known Ports Enter (1)
Δ To UDP Scan Well Known Ports Enter (2)
Δ To Comprehensive Scan Enter (3)
Δ To Regular Scan Enter (4)
Δ To Scan TCP Ports in Specific Range (5)
Δ To IP OS Detection Enter (6)
Δ To Exit Enter (99)

#""")


def main_list():
    return ("""\n
----------------------------------------------
Please enter the type of Scan you want to run: 
----------------------------------------------
Δ IP Address Scan (1)
Δ Domain Name Look-up (2)
Δ Exit Enter (99)

#""")


def TcpScan(ip):
    print("-" * 50)
    print("TCP Scanning host T -> {}".format(ip))
    print("Time started: {}".format(dt.now()))
    timeStart = dt.now()
    print("-" * 50)

    print("Nmap Version: ", scanner.nmap_version())  # print Nmap Version to user
    # v is used for verbose, which means if selected it will give extra information
    # 1-1024 means the port number we want to search on
    # -sS means perform a TCP SYN connect scan, it send the SYN packets to the host
    scanner.scan(ip, '1-1024', '-v -sV -sS ')
    print(scanner.scaninfo())
    # state() tells if target is up or down
    print("IP Status: ", scanner[ip].state())
    # all_protocols() tells which protocols are enabled like TCP UDP etc
    print("Enabled Protocols:", scanner[ip].all_protocols())
    # open port that using tcp protocol
    print("Open Ports: ", list(scanner[ip]['tcp'].keys()), "\n")

    for i in scanner[ip]['tcp']:
        portInfo = scanner[ip].tcp(int(i))
        print("Port#", i)
        print("----------------------------------------------")
        for key, value in portInfo.items():
            print(key, ':', value)
        print("\n\n\n")

    print("-" * 50)
    print("<- Scan Completed ->")
    totaltime = dt.now() - timeStart  # calculate total time for scanning
    print("Scan run for: {}".format(totaltime))
    print("-" * 50)


def UdpScan(ip):
    print("-" * 50)
    print("UDP Scanning host T -> {}".format(ip))
    print("Time started: {}".format(dt.now()))
    timeStart = dt.now()
    print("-" * 50)
    # 1-1024 means the port number we want to search on
    # -sU means perform a UDP SYN connect scan, it send the SYN packets to #the host
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip, '0-1024', '-v -sU -sV')
    # Scan Gernal info
    udpinfo = list(scanner.scaninfo().values())
    udpinfo = list(udpinfo[0].values())
    print("method", udpinfo[0])
    print("Services:", udpinfo[1])
    # state() tells if target is up or down
    print("Ip Status:", scanner[ip].state())
    # all_protocols() tells which protocols are enabled like TCP UDP etc
    print("Enabled Protocols:", scanner[ip].all_protocols())
    # open port that using UDP protocol
    print("Open Ports:", scanner[ip]['udp'].keys(), "\n")

    for i in scanner[ip]['udp']:
        portInfo = scanner[ip].tcp(int(i))
        print("Port#", i)
        print("----------------------------------------------")
        for key, value in portInfo.items():
            print(key, ':', value)
        print("\n\n\n")

    print("-" * 50)
    print("<- Scan Completed ->")
    totaltime = dt.now() - timeStart  # calculate total time for scanning
    print("Scan run for: {}".format(totaltime))
    print("-" * 50)


def ComprehensiveScan(ip):
    print("-" * 50)
    print("Comprehensive Scan -> {}".format(ip))
    print("Time started: {}".format(dt.now()))
    timeStart = dt.now()
    print("-" * 50)

    print("Nmap Version: ", scanner.nmap_version())
    # sS for SYN scan, sv probe open ports to determine what service and version they are running on
    # O determine OS type, A tells Nmap to make an effort in identifying the target OS
    scanner.scan(ip, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip].state())
    print("Enabled Protocols:", scanner[ip].all_protocols())

    print("Open Ports: ", scanner[ip]['tcp'].keys(), "\n")

    for i in scanner[ip]['tcp']:
        portInfo = scanner[ip].tcp(int(i))
        print("Port#", i)
        print("----------------------------------------------")
        for key, value in portInfo.items():
            print(key, ':', value)
        print("\n\n\n")

    print("-" * 50)
    print("<- Scan Completed ->")
    totaltime = dt.now() - timeStart  # calculate total time for scanning
    print("Scan run for: {}".format(totaltime))
    print("-" * 50)


def RegularScan(ip):
    print("-" * 50)
    print("Regular Scan -> {}".format(ip))
    print("Time started: {}".format(dt.now()))
    timeStart = dt.now()
    print("-" * 50)
    # Works on default arguments
    scanner.scan(ip)
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip].state())
    print(scanner[ip].all_protocols())
    print("Enabled Protocols:", scanner[ip].all_protocols())
    print("Open Ports: ", scanner[ip]['tcp'].keys(), "\n")

    for i in scanner[ip]['tcp']:
        portInfo = scanner[ip].tcp(int(i))
        print("Port#", i)
        print("----------------------------------------------")
        for key, value in portInfo.items():
            print(key, ':', value)
        print("\n\n\n")

        print("-" * 50)
        print("<- Scan Completed ->")
        totaltime = dt.now() - timeStart  # calculate total time for scanning
        print("Scan run for: {}".format(totaltime))
        print("-" * 50)


def OSDetection(ip):
    print("-" * 50)
    print("OS Detection ~> {}".format(ip))
    print("-" * 50)
    print(scanner.scan(ip, arguments="-O")['scan'][ip]['osmatch'][1])


def ScanPortRange(ip):
    open_ports = []
    while True:
        print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
        port_range = input("Enter port range: ")
        #Check if the range is valid
        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        if port_range_valid:
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            break

    for port in range(port_min, port_max + 1):
        try:
            result = scanner.scan(hosts=ip, arguments=f"-sS -p {port}")
            port_status = (result['scan'][ip]['tcp'][port]['state'])
            port_name = (result['scan'][ip]['tcp'][port]['name'])
            if port_status == "open":
                print(f"Port {port_name}({port}) is {port_status}")
        except Exception as ex:
            print(f"Cannot scan port {port}.")




def valid_ip():
    while True:
        ip = input("Enter target IP address (or 0 to  Main List):")
        ip = ip.strip()
        #Check if IP is valid
        if ip_add_pattern.search(ip):
            print("\n")
            print(f"{ip} is a valid ip address")
            try:
                hostname = socket.gethostbyaddr(ip)[0]  # DNS
                print("Host Name of the Target (DNS):", hostname)
            except:
                print("Host name not found ! ->")

            return ip
        elif ip == '0':
            return '0'
        else:
            print(f"{ip} is a invalid ip address !")


def FindARec(HostName):
    #indicates the IP address of a given Domain
    print("\n")
    print("-" * 50)
    print("A Record")
    print("-" * 50)
    result = my_resolver.resolve(HostName, "A")
    for val in result:
        print('A Record: ', val.to_text())
        DNSFile.write('A Record: ' + val.to_text() + "\n")


def FindPRTRed(ip):
    #indicates the Domain of a given IP address)
    print("\n")
    print("-" * 50)
    print("PRT Record:")
    print("-" * 50)
    try:
        result = my_resolver.resolve(ip + '.in-addr.arpa', 'PTR')
        for val in result:
            print('PTR Record: ', val.to_text())
            DNSFile.write('PTR Record: '+ val.to_text() +"\n")
    except Exception as e:
        print(e)
        print(" <- PRT record doesn't exist! ->")


def FindNSRec(HostName):
    #all DNS records for a domain
    print("\n")
    print("-" * 50)
    print("NS Record")
    print("-" * 50)
    result = my_resolver.resolve(HostName, 'NS')
    # Printing record
    for val in result:
        print('NS Record: ', val.to_text())
        DNSFile.write('NS Record: '+ val.to_text()+ "\n")

def GetLocatinoIp(ip):
    #Location of IP Address
    print("\n")
    print("-" * 50)
    print("Location Information:")
    DNSFile.write("Location Information \n")
    print("-" * 50)
    ipApi = f'http://ip-api.com/json/{ip}'
    req = requests.get(ipApi).json()
    print("Countery: ", req["country"])
    print("City: ", req["city"])
    print("ISP:", req["isp"])
    print("Lat:", req["lat"])
    print("Lon:", req["lon"])
    DNSFile.write("Countery: "+ req["country"] +"\n")
    DNSFile.write("City: "+ req["city"] +"\n")
    DNSFile.write("ISP:"+ str(req["isp"]) +"\n")
    DNSFile.write("Lat:"+ str(req["lat"]) +"\n")
    DNSFile.write("Lon:"+ str(req["lon"]) +"\n")

def WhoisInfo(HostName):
    #retrieving WHOIS information of domains
    print("\n")
    print("-" * 50)
    print("Whois Information")
    print("-" * 50)
    try:
        domainInfo = whois.whois(HostName)
        for key, value in domainInfo.items():
            print(key, ':', value)
            DNSFile.write(key +": " +str( value) +"\n")

    except Exception as e:
        print(e)
        print(" <- Domain doesn't exist! ->")


def CheckStatus(Hostname):
    # DNS Info and Status
    print("\nDNS Info", Hostname)
    DNSFile.write("DNS Info"+ Hostname +"\n")
    ip = socket.gethostbyname(f"{Hostname}")
    NewHost = (f"http://{Hostname}")
    status = requests.get(f"{NewHost}")
    StatusCode = status.status_code
    serverreq = status.headers
    res = serverreq.get("Server")
    WebTech = builtwith.parse(f"{NewHost}")
    print("-" * 50)
    print("General Information")
    print("-" * 50)
    print(f"Domain:{Hostname} ", f"IP: {ip}: " f"Status Code: {StatusCode}..Ok ")
    DNSFile.write("Domain: "+ Hostname +" IP: "+ str(ip) +" Status Code: " +str(StatusCode) +"\n")
    print("Web Technolgy:")
    print("Server: ", res)
    DNSFile.write("Server: " + res+"\n")
    print("Programming Language : ", WebTech.get("programming-languages"))
    DNSFile.write("Programming Language : "+ str(WebTech.get("programming-languages"))+"\n")
    print("Cms:", WebTech.get("cms"))
    DNSFile.write("Cms:"+ str(WebTech.get("cms")) +"\n")
    print("JavaScript Framework:", WebTech.get("javascript-frameworks"))
    DNSFile.write("JavaScript Framework:"+ str(WebTech.get("javascript-frameworks"))+"\n")
    print("\n")
    print("-" * 50)
    print("Top 100 Open Ports:")
    print("-" * 50)

    for port in TopPorts:
        port = int(port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(2)
        result = s.connect_ex((Hostname, port))
        try:
            if result == 0:
                Services = socket.getservbyport(port)
                print(f"Port {port} is Open", Services.format(port))
                DNSFile.write("Port " + str(port)+" is Open "+ Services.format(port) +"\n")
        except OSError:
            pass
        s.close()


def CheckTLSVer(HostName):
    #Transport Layer Security Version
    print("\n")
    print("-" * 50)
    print("TLS Version:")
    DNSFile.write("TLS Version:")
    print("-" * 50)
    Res = ssl.SSLContext()
    try:
        with socket.create_connection((HostName, 443)) as sock:
            with Res.wrap_socket(sock, server_hostname=HostName) as sock1:
                print(sock1.version())
                DNSFile.write(sock1.version()+"\n")
    except:
        pass


while True:
    try:
        #To write DNS LookUp to the user as output
        DNSFile = open("DNSlookup.txt", 'w')

        # A File Contain Top 100  Used Potrts
        FileTopPorts = open("Top100Ports.txt", 'r')
        TopPorts = FileTopPorts.read().splitlines()
        FileTopPorts.close()
        response = input(main_list())
        print("\nYou have selected option: ", response)

        # Scan IP
        if response == '1':
            ip = valid_ip()
            while True and ip != '0':
                response = input(ip_command_list())
                print("\nYou have selected option: ", response)

                # 1 perform a TCP Scan
                if response == '1':
                    TcpScan(ip)

                # 2 perform a UDP Scan
                elif response == '2':
                    UdpScan(ip)

                # 3 Comprehensive Scan
                elif response == '3':
                    ComprehensiveScan(ip)


                # 4 perform a Regular Scan
                elif response == '4':
                    RegularScan(ip)


                # 5 ScanPortRange
                elif response == '5':
                    ScanPortRange(ip)


                # 6 OS Detection
                elif response == '6':
                    OSDetection(ip)


                elif response == '99':
                    print("Thank you for using IP Scanner! ->")
                    break

                else:
                    print("Incorrect Input .. please try again! ->")

                print("\n\n\n")


        # Domian Name Server
        elif response == '2':

            Hostname = input("\nEnter The Host (" + Fore.BLUE + "ex : example.com" + Fore.RESET + ") -> ")
            ip = socket.gethostbyname(f"{Hostname}")
            FindARec(Hostname)
            FindPRTRed(ip)
            FindNSRec(Hostname)
            WhoisInfo(Hostname)
            GetLocatinoIp(ip)
            CheckStatus(Hostname)
            CheckTLSVer(Hostname)
            print("\n\n\n")


        elif response == '99':
            print("Thanks to Using our Tool Good Time! ->")
            break

        else:
            print("Incorrect Input .. please try again! ->")


        FileTopPorts.close()

        print("\n\n\n")


    except KeyboardInterrupt:  # If the user interputs the program
        print("<- Terminating Scan ->")
        sys.exit()

    except socket.gaierror:  # If the hostname could not be resolved or no successful connection could be made with the host
        print("<- !Hostname could not be resolved! ->")
        print("<- !Couldn't connect to server! ->")


    except Exception as e:
        print(e)


DNSFile.close()

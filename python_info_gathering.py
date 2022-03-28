from colorama import Fore, Back, Style
import nmap
import whois
import requests
from googlesearch import search
import time
import sys
import warnings

my_logo = """
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                🇵  🇾  🇹  🇭  🇴  🇳     🇸  🇨  🇦  🇳  🇳  🇪  🇷    
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
"""
print(Fore.CYAN  + my_logo)


def port_scanner(target, ports):
    """
    This method will scan the range of ports provided on given target and returns the data
    """
    scanner = nmap.PortScanner()
    scanner.scan(target, ports)
    # print(scanner.scan(target, ports))

    for host in scanner.all_hosts():
        host_name = scanner[host].hostname()
        print(f"Host:: {host} ( {host_name} ) ")
        print(f"State:: {scanner[host].state()}")

        # print(scanner[host].all_protocols())
    
        for protocol in scanner[host].all_protocols():
            print("----------- Protocols -----------")
            print(f"Protocol:: {protocol}")

            lport = scanner[host][protocol].keys()
            
            print("---------- Open Ports ----------")
            for port in lport:
                state = scanner[host][protocol][port]['state']
                print(f"port : {port} \t state : {state}")


def os_detection(target):
    """
    This function will get the OS Information of the target
    """
    warnings.warn("OS Detection was not always accurate")
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-O")
    # print(scanner.scan(target, arguments="-O"))
    for host in scanner.all_hosts():
        host_name = scanner[host].hostname()
        if host_name == "":
            print(f"Host:: {host}")
        else:
            print(f"Host:: {host} ( {host_name} ) ")
        print(f"State:: {scanner[host].state()}")
    
        if scanner[host]['osmatch']:
            print("--------------------- Operating System ---------------------")
            print(f"Operating System:: {scanner[host]['osmatch'][1]['name']} \t Accuracy:: {scanner[host]['osmatch'][1]['accuracy']}")

            print("\n--------------------- Vendor ---------------------")
            print(f"Vendor:: {scanner[host]['osmatch'][1]['osclass'][0]['vendor']}")
        else:
            print("Unable to find the Operating System Detaiils")


def ping_scan(target):
    """
    This function will Scans the list of devices up and running on a given subnet.
    """
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sP')

    for host in scanner.all_hosts():
        host_name = scanner[host].hostname()
        print("\n")
        print(f"Host:: {host} ( {host_name} ) ")
        print(f"State:: {scanner[host].state()}")


def single_host_scan(target):
    """
    This funtion will Scans a single host for 1000 well-known ports. These ports are the ones used by popular services like SQL, SNTP, apache, and others.
    """
    scanner = nmap.PortScanner()
    scanner.scan(target)

    for host in scanner.all_hosts():
        print(f"Host:: {host}")
        print(f"State:: {scanner[host].state()}")
        print(f"Protocol:: {scanner[host].all_protocols()}")

        if scanner[host].all_protocols():
            print("----------------- Open Ports -----------------")
            open_ports = scanner[host]['tcp']
            for port in open_ports.items():
                print(f"Port : {port[0]} \t State : {port[1]['state']} \t Service : {port[1]['name']} \t Product : {port[1]['product']}")
        else:
            print("No Protocols Scanned")


def aggressive_scan(target):
    """
    This function will be aggressive mode that enables OS detection, version detection, script scanning, and traceroute.
    """
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-A')

    for host in scanner.all_hosts():
        print(f"Host:: {host}")
        print(f"State:: {scanner[host].state()}")
        print(f"Protocol:: {scanner[host].all_protocols()}")

        if scanner[host].all_protocols():
            print("----------------- Open Ports -----------------")
            open_ports = scanner[host]['tcp']
            for port in open_ports.items():
                print(f"Port : {port[0]} \t State : {port[1]['state']} \t Service : {port[1]['name']} \t Product : {port[1]['product']}")

                if port[0] == 3389:
                    print("-------------- 3389 Info --------------")
                    print(port[1]['script']['rdp-ntlm-info'])

                if port[0] == 80:
                    print("-------------- 80 Info --------------")
                    print(port[1]['script']['http-server-header'])
                    print(port[1]['script']['http-title'])
                
                if port[0] == 443:
                    print("-------------- 443 Info --------------")
                    print(port[1]['script']['http-server-header'])
                    print(port[1]['script']['ssl-cert'])
        else:
            print("No Protocols Scanned")


def whois_scan(target):
    """
    Whois is an Internet service and protocol that searches and displays information pertaining to a domain name 
    from repositories of domain name registrars worldwide. 
    """
    print("-------------------- Whois --------------------")
    scanner = whois.query(target)
    data = scanner.__dict__
    for item in data.items():
        print(item[0] + ' = ', item[1])


def subdomain_finder(target):
    """
    This function will fetch the Subdomain of the given target
    """
    print("-------------------- Subdomains finder --------------------")
    
    with open('subdomain_names.txt', 'r') as file:
        name = file.read()
        sub_domains = name.splitlines()

        print('-------------------- URL after scanning subdomains --------------------')

        for sub_domain in sub_domains:
            url = f"https://{sub_domain}.{target}"
            # print(url)

            try:
                requests.get(url)
                print(f"[+] {url}")

            except requests.ConnectionError:
                pass
    print('\n')
    print('----------- Scanning Finished ------------')
    print('-------------------- Scanner Stopped --------------------')


def dork_search_query():
    try:
        dork = input("\n[+] Enter The Dork Search Query: ")
        amount = input("[+] Enter The Number Of Websites To Display: ")
        print ("\n ")

        requ = 0
        counter = 0

        for results in search(dork, tld="com", lang="en", num=int(amount)):
            counter = counter + 1
            print ("[+] ", counter, results)
            time.sleep(0.1)
            requ += 1
            if requ >= int(amount):
                break

            # data = (counter, results)

            # # print(data)
            time.sleep(0.1)

    except KeyboardInterrupt:
            print ("\n")
            time.sleep(0.5)
            sys.exit(1)

    print ("[•] Done... Exiting...")
    sys.exit()



print("""Enter the Option to be Searched:: 
                    1. Port Scan 
                    2. OS Detection
                    3. Ping Scan
                    4. Single Host Scan
                    5. Aggressive Scanning
                    6. Whois
                    7. Subdomain Finder
                    8. Dorks
                    """)

option = int(input("Selected Option:: "))

if option == 1:
    target = input("Enter the Target:: ")
    port_range = input("Enter the Port range:: ")
    port_scanner(target=target, ports=port_range)
elif option == 2:
    target = input("Enter the Target:: ")
    os_detection(target=target)
elif option == 3:
    target = input("Enter the Target:: ")
    ping_scan(target=target)
elif option == 4:
    target = input("Enter the Target:: ")
    single_host_scan(target=target)
elif option == 5:
    target = input("Enter the Target:: ")
    aggressive_scan(target=target)
elif option == 6:
    target = input("Enter the Target:: ")
    whois_scan(target=target)
elif option == 7:
    target = input("Enter the Target:: ")
    subdomain_finder(target=target)
elif option == 8:
    dork_search_query()


    

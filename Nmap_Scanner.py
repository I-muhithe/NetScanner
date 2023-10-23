#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Creating a nmap scanner tool using python")
print("<----------------------------------------------------->")


ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n""")
print("You have selected option: ", resp)
resp_descr={'1':['-v -sS','tcp'],'2':['-v -sU','udp'],'3':['-v -sS -sV -sC -A -O','tcp']}
if resp not in resp_descr.keys():
    print("enter a valid option")
else:
    print("nmap version: ", scanner.nmap_version())
    scanner.scan(ip_addr,"1-1024",resp_descr[resp][0]) #the # are port range to scan, the last part is the scan type
    print(scanner.scaninfo())
    if scanner.scaninfo()=='up':
        print("Scanner Status: ",scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ",scanner[ip_addr][resp_descr[resp][1]].keys())  #display all open ports

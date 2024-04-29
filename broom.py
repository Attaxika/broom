#Broom.py
#Author: Attaxika
#Updated: 2024-04-17

#Imports
import ipaddress
import socket
import os
import subprocess

#Main
def main():
    #Header
    try:
        print(".Alright, let's\nstart sweepin'.\n...............\n.............//\n............//.\n...........//..\n..........//...\n.........//....\n........//.....\n.......//......\n...‰‰‰‰‰‰‰‰‰‰‰.\n..///////////..\n././././././...\n~‰‰»‡‰‰~‰‰»~»‰‡\n")
    except SyntaxError:
        pass
    print("This program is a lightweight network sweeping tool intended for quick enumeration\n")
    IPs = input("Enter IPs (comma separated, accepts CIDR): ").split(",")
    portsToScan = [80, 443, 21, 22, 23, 25, 53, 110, 111, 139, 445, 512, 513, 514, 1433, 1521, 2049, 3306, 3389, 5432, 5632, 5900, 5901]
    found = []
    foundPorts = []
    portCheck = ""
    verbose = ""
    while not ((portCheck == "y") or (portCheck == "n") or (portCheck == "c")):
        print("Scan for open ports too?\ny=All ports (THIS WILL TAKE SIGNIFICANTLY LONGER)\nn=No\nc=Common ports")
        portCheck = input("(y/n/c)").lower()
    while not ((verbose == "y") or (verbose == "n")):
        verbose = input("Verbose output? (y/n) ").lower()
    if portCheck == "y":
        portsToScan = list(range(1, 65535))

    #Validate IPs
    for ip in IPs:
        try:
            ipaddress.ip_network(ip, strict=False)
            if "/" in ip:
                #Convert CIDR to list of IPs
                network = ipaddress.ip_network(ip)
                for item in network.hosts():
                    IPs.append(str(item))
                continue

            #Ping IP, redirect output to /dev/null
            if "posix" in os.name:
                result = subprocess.call(['ping', '-c', '1', '-W', '1', ip], stdout=open('/dev/null', 'w'))
            else:
                result = subprocess.call(['ping', '-n', '1', '-w', '1', ip], stdout=open('NUL', 'w'))
            if result == 0:
                found.append("IP is up: %s" % ip)
                if verbose == "y":
                    print("IP is up: %s" % ip)
                if portCheck != "n":
                    scan(ip, portsToScan, verbose, foundPorts)
            else:
                if verbose == "y":
                    print("IP is down: %s" % ip)            
        except ValueError as e:
            print("IP failed to validate: %s" % ip)
            print("If your IP contained a CIDR, ensure that your CIDR is correct for the subnet")
            print(e)
            IPs.remove(ip)
            continue

    #Print results
    try:
        save = ""
        output = ""
        portStr = ""
        while not ((save == "y") or (save == "n")):
            save = input("Save results to file? (y/n) ").lower()
        if save == "y":
            output = open("broom_results.txt", "w")
        if (portCheck == "y") or (portCheck == "c"):
            for ip in found:
                ip_address = ip.split(":")[1].strip()
                portStr = [port for port in foundPorts if ip_address in port]
                if len(portStr) != 0:
                    print("Found ports for %s: " % ip_address)
                    print("\n".join(portStr))
                    if save == "y":
                        output.write("Found ports for %s:\n" % ip_address)
                        output.write("\n".join(portStr) +"\n")
                else:
                    print("IP up, but no ports found: %s\n" % ip_address)
                    if save == "y":
                        output.write("IP up, but no ports found: %s\n" % ip_address)
        else:
            print("IPs found:")
            print("\n".join(found))
            if save == "y":
                for ip in found:
                    output.write(ip+"\n")
    except Exception as e: 
        print("Failed to write to file. Does this script have permission to do so?")
        print(e)

def scan(ip, portRange, verbose, foundPorts):
    for port in portRange:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.01)
        try:
            sock.connect((ip, port))
            foundPorts.append("\tPort %s is open on %s" % (port, ip))
            if verbose == "y":
                print("Port %s up" % port)
            sock.close()
        except socket.error:
            if verbose == "y":
                print("Port %s down" % port)
            sock.close()
            continue
try:
    main()
except KeyboardInterrupt:
    print("Exiting...")

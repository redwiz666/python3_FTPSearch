#!/bin/python3
# Script to scan a Host/Network and find anonymously FTP

import threading, socket, ipaddress, queue, ftplib

# Used to print from the Threads
print_lock = threading.Lock()

# Define Global Variables
hosts_queue = queue.Queue()

class FTPsearch:
    # Function to check if FTP port is open
    def port_scan(host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            with print_lock:
                print(f"[-] Checking: {host}")
            try:
                s.connect((host, int(port)))
                with print_lock:
                    print(f"[+] Found FTP at: {host} \n [*] trying anonymous login")
                FTPsearch.login(host)
            except socket.error as e:
                with print_lock:
                    if "Connection refused" in e.strerror:
                        # Port not open for connection
                        pass
                    elif "No route" in e.strerror:
                        # Host not online
                        pass
                    else:
                        print(f"[{host}] Error: " + e.strerror)


    # Function to login to FTP as Anonymous
    def login(host):
        try:
            with ftplib.FTP(host) as ftp:
                tmp = ftp.login()
                if "230" in tmp:
                    with print_lock:
                        print(f"[{host}] Anonymous Login allowed")
                        ftp.getwelcome()
        except ftplib.all_errors as e:
            if "Login incorrect" in str(e).split(None, 1)[1]:
                with print_lock:
                    print(" [*] Anonymous Login Not Allowed")
            else:
                with print_lock:
                    print(f"[{host}] Error: " + str(e).split(None, 1)[1])


def process_queue():
    while not hosts_queue.empty():
        tmp_host = hosts_queue.get()
        FTPsearch.port_scan(tmp_host, "21")
        hosts_queue.task_done()


def main():
    rhost = input("Enter Target: (Ex. 192.168.229.0/24 or 192.168.229.105) ")
    # Check if the Input address is a Network with CIDR
    if "/" in rhost:
        try:
            # Check if there is a network ID
            for ip in ipaddress.IPv4Network(rhost, False):
                if str(ip).split(".")[3] != "0":
                    hosts_queue.put(str(ip))
        except ipaddress.AddressValueError as e:
            print(e)
    else:
        try:
            # Passing the rhost into ipaddress.IPv4Address allows for us to verify its correct
            hosts_queue.put(str(ipaddress.IPv4Address(rhost)))
        except ipaddress.AddressValueError as e:
            print(e)
            main()

    # Create Threads for Scanning (default = 100)
    for x in range(100):
        t = threading.Thread(target=process_queue())
        t.daemon = True
        t.start()

    hosts_queue.join()


if __name__ == "__main__":
    main()

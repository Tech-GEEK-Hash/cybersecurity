import argparse
import nmap

def argument_parser():
    parser = argparse.ArgumentParser(description="Port scanner that detects if a host is live and scans specified ports.")
    parser.add_argument("-o", "--host", nargs="?", help="Host IP address", required=True)
    parser.add_argument("-p", "--port", nargs="?", help="Comma-separated port list, such as '25,80,8000'", required=True)
    parser.add_argument("-t", "--type", choices=['tcp', 'udp'], default='tcp', help="Protocol type: 'tcp' or 'udp' (default: 'tcp')")
    return vars(parser.parse_args())

def check_host_live(nm_scan, host_id):
    nm_scan.scan(host_id, arguments='-sn')  
    if nm_scan.all_hosts():
        if nm_scan[host_id].state() == "up":
            return True
    return False

def nmap_scan(host_id, port_num, nm_scan, protocol):
    if protocol == 'tcp':
        nm_scan.scan(host_id, port_num)
        state = nm_scan[host_id]['tcp'][int(port_num)]['state']
        name = nm_scan[host_id]['tcp'][int(port_num)]['name']
        result = f"[*] {host_id} tcp/{port_num} {state} {name}"
    elif protocol == 'udp':
        nm_scan.scan(host_id, port_num, arguments='-sU')
        state = nm_scan[host_id]['udp'][int(port_num)]['state']
        name = nm_scan[host_id]['udp'][int(port_num)]['name']
        result = f"[*] {host_id} udp/{port_num} {state} {name}"
    
    return result

if __name__ == '__main__':
    try:
        user_args = argument_parser()
        host = user_args["host"]
        ports = user_args["port"].split(",")
        protocol = user_args["type"]

        nm_scan = nmap.PortScanner()

        if check_host_live(nm_scan, host):
            print(f"[+] Host {host} is live")
            for port in ports:
                print(nmap_scan(host, port, nm_scan, protocol))
        else:
            print(f"[-] Host {host} is not live or unreachable")

    except KeyError as e:
        print(f"Error: Missing argument {e}. Please provide the command line argument before running.")
    except Exception as e:
        print(f"An error occurred: {e}")

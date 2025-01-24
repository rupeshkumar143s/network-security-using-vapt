import nmap
def scan_website(target):
 nm = nmap.PortScanner()
# Add custom arguments if needed
 nm.scan(target, arguments='-p 80,443')
 # Print scan results
 for host in nm.all_hosts():
 if nm[host].state() == 'up':
 print(f"Host: {host}")
 for proto in nm[host].all_protocols():
 ports = nm[host][proto].keys()
 for port in ports:
 state = nm[host][proto][port]['state']
 if state == 'open':
 print(f"Open Port: {port}")
# Provide the target website or IP address
target = " athira20000.github.io "
# Call the function to scan the target
scan_website(target)

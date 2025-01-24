import nmap
import os
import subprocess
from weasyprint import HTML
# Define the target URL to scan
target_url = "https://athira20000.github.io"
# Run nmap to find open ports
nm = nmap.PortScanner()
nm.scan(hosts=target_url, arguments="-p-")
# Extract the open ports from the nmap results
open_ports = []
for host in nm.all_hosts():
print("Nmap scan results for:", host)
print("Host is", nm[host].state())
for proto in nm[host].all_protocols():
print("Protocol:", proto)
lport = list(nm[host][proto].keys())
lport.sort()
for port in lport:
print("Port:", port, "\tState:", nm[host][proto][port]['state'])
# Construct the target string for wapiti
target_string = target_url + ":" + ",".join(open_ports)
# Run wapiti on the target URL to generate the VAPT report
command = "wapiti -u " + target_string + " -f html -o /home/athira/Desktop/generated_report"
os.system(command)
# Convert the HTML report
report_file = "/home/athira/Desktop/generated report" + target_url. Replace ("/", "_").strip() +
"_wapiti_report.html"

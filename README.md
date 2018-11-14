# DNS Spoofer

Program to intercept forwarded traffic on a network and spoof the DNS of HTTP traffic (Note: does not work https)

Requirements:

[+]  Python 2.5 and above

[+]  NetfilterQueue is a C extention module that links against libnetfilter_queue. Before installing, ensure you have:

     A C compiler
     Python development files
     Libnetfilter_queue development files and associated dependencies

[+]  Run command build python development files: apt-get install build-essential python-dev libnetfilter-queue-dev

[+]  NetfilterQueue 0.8.1 and above (pip install netfilterqueue)

Usage:

Create a rule in the FORWARD chain in iptables as follows: iptables -I FORWARD -j NFQUEUE --queue-num [any number]

python dns_spoof.py

python3 dns_spoof.py

Read more about NetfilterQueue here: https://pypi.org/project/NetfilterQueue/

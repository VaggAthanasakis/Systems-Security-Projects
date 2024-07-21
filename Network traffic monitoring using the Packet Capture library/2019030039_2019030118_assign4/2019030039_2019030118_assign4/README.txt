Authors:
Athanasakis Evangelos
Fragkogiannis George 

GCC Version:
gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0

-------------------------------------- Compilation --------------------------------------------
- In order to compile the pcap.c program you have to run the command make in order to create the executable file "pcap_ex"

-----------------------------------------------------------------------------------------------
In this project, we create a networking monitoring tool based on the C programming
language. We utilize the packet capture library (libpcap), where this library
allows you to to capture the packets from the network interface of the executed device.
More specifically:
1. We process traffic in two modes
    a. Online: monitoring the traffic live from a network interface (pcap_open_live)
    b. Offline: read a pcap file (pcap_open_offline).
    2. For this project, we capture network traffic and we process the incoming TCP and UDP packets

-----------------------------------------------------------------------------------------------
The tool will receive the required arguments from the command line upon execution
as such:
Options:

-i Select the network interface name (e.g., eth0)
-r Packet capture file name (e.g., test.pcap)
-f Filter expression in string format (e.g., port 8080)
-h Help message, which show the usage of each parameter

Examples of the execution:
● ./pcap_ex -i eth0 (save the packets in log.txt)
● ./pcap_ex -r test_pcap_5mins.pcap (print the outputs in terminal)
● ./pcap_ex -i eth0 -f “port 8080”

** For this project, the filter is considered to be the destination port number
** Retransmition detection is only possible when the packet's protocol is TCP, since
   UDP is a connectionless protocol and we cannot mark the retransmited packets.
   On the other hand, TCP establishes a connection between the sender and the receiver 
   and has built-in flags (TH_RST) that can indicate if the packet is retransmited.


Authors:
Athanasakis Evangelos
Fragkogiannis George 

GCC Version:
gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0

-----------------------------------------------------------------------------------------------------
In this assignment, we got familiar with iptables rules. Iptables is used to set up, maintain,
and inspect the tables of IP packet filter rules in the Linux kernel. Several different tables may be
defined. Each table contains a number of built-in chains and may also contain user-defined
chains. Each chain is a list of rules which can match a set of packets. Each rule specifies what to
do with a packet that matches.

-----------------------------------------------------------------------------------------------------
The adblock.sh script is responsible for generating a set of firewall rules that block access for
specific network domain names.

adblock.sh script is expected to do the following:
1. Configure adblock rules based on the domain names of “domainNames.txt” file.
2. Configure adblock rules based on the IP addresses of “IPAddresses.txt”.
3. Save rules to “adblockRules” file (this file does not have a filename extension).
4. Load rules from “adblockRules” file (this file does not have a filename extension).
5. Reset rules to default settings (i.e. accept all).
6. List current rules.

Tool Specification:
The script will receive the following arguments from the command line upon execution.
Options:
-domains     Configure adblock rules based on the domain names of `domainNames.txt’ file
-ips         Configure adblock rules based on the IP addresses of `IPAddresses.txt’ file.
-save        Save rules to ‘adblockRules’ file.
-load        Load rules from ‘adblockRules’ file.
-list        List current rules.
-reset       Reset rules to default settings (i.e. accept all).
-help        Display help and exit
============================================================================================
For the -domains and -ips tools: 
the script will read each line of the domainNames.txt file and generate an iptables ad blocking rule of this format:
                    sudo iptables -A INPUT -s "domain or ip" -j REJECT
When using -domains we use a domain name as an argument and when using -ips we block for each of the found ip
addresses for a specific domain.

+By using the -A INPUT argument appending a rule to the INPUT chain. The INPUT chain is responsible for filtering 
incoming packets to the local system.

+By using the -s argument we specify the source IP address or domain name to which the rule will apply. 

+REJECT, means that the packet will be rejected, and an appropriate response will be sent back to the source, 
indicating that the packet has been rejected.

============================================================================================
For the -load tool: 
We print in the terminal the list of rules currently configured in the iptables firewall on a Linux system.
This is implemented by using the "iptables -L" command.

============================================================================================
For the -reset tool:
Resets rules to default settings (i.e. accept all) using "sudo iptables -F" command.
The adblockRules file is also emptied by using "truncate -s 0 "$adblockRules"" 

============================================================================================
For the -list tool:
Prints the ad block rules in the adblockRules file NOT the rules implemented in iptables

============================================================================================
For the -save tool:
Adds all rules inside the adblockRules file to the iptables firewall. This is done by reading each line of the 
adblockRules file and executing it using eval.


#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Configure adblock rules based on the domain names of $domainNames file.
        
        # Ensure the domain file exists
        if [ ! -f "$domainNames" ]; then
            echo "Error: Domain file '$domainNames' not found."
            exit 1
        fi
        truncate -s 0 "$adblockRules"

        # Reads every line from the domainName.txt to get domains to block
        # by generating a generic AdBlock block rule
        while IFS= read -r domain || [ -n "$domain" ]; do  # This condition ensures that the loop continues to execute 
            echo "sudo iptables -A INPUT -s "$domain" -j REJECT" >> "$adblockRules"           # as long as there is either a line to read or the variable 
                                                                                # $domain is not empty.
                                                                                # The rules are saved in the adblockRules
        done < "$domainNames"

        true
            
    elif [ "$1" = "-ips"  ]; then
        truncate -s 0 "$adblockRules" #Empty old rules 

        # Configure adblock rules based on the IP addresses of $IPAddresses file.
        # We find the ips of the domains given from the file names and 
        # save them in IPAddresses.txt
        while IFS= read -r domain || [ -n "$domain" ]; do
            # Use dig to fetch the IP address for the domain
            ip_address=$(dig +short "$domain") # By using short we can get only the ip address 
            
            # Process each IP address separately
            while IFS= read -r ip && [ -n "$ip" ]; do # If the read command is successful (returns a zero status) 
                                                      # and the variable $ip is non-empty, the loop continues. 
                # Handle each IP address as needed
                echo "sudo iptables -A INPUT -s "$ip" -j REJECT" >> "$adblockRules"
            done <<< "$ip_address"            
        done < "$domainNames"


        # Then we create adblock block rules from the ips saved in the file and 
        # temporarily save them in the current_rules file 
        # Reads every line from the domainName.txt to get domains to block
        # by generating a generic AdBlock block rule
        #while IFS= read -r domain || [ -n "$domain" ]; do   # This condition ensures that the loop continues to execute 
            


            #echo "||$domain^" >> "$current_rules"           # as long as there is either a line to read or the variable 
                                                            # $domain is not empty.
                                                            # The rules are saved in the current_rules array 
        #done < "$IPAdresses"
        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        while read -r rule; do     # apply each rule
            eval "$rule"
        done < "$adblockRules"
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.    
        iptables -L
        true

    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        truncate -s 0 "$adblockRules" 
        sudo iptables -F
        true

    elif [ "$1" = "-list"  ]; then
        # List current rules.
        cat "$adblockRules"
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0
#!/bin/sh

echo "executing client routing commands!"
echo "ip rule add not from all fwmark 0x5EC0070C lookup 3542"
ip rule add not from all fwmark 0x5EC0070C lookup 3542
echo "ip rule add from all lookup main suppress_prefixlength 0"
ip rule add from all lookup main suppress_prefixlength 0

echo "don't forget to add the VPN route to table 3542 after running the program!"
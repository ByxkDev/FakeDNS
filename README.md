I've rewritten the original Python script into JavaScript to improve usability and integration within my own project. This change enhances compatibility for developers working in JavaScript environments and streamlines maintenance. The new version maintains all original functionality while leveraging JavaScript’s strengths for easier deployment and extension. After all big thanks to Crypt0s.

# Official Python Script
https://github.com/Crypt0s/FakeDns

# FakeDNS

Now with round-robin & improved options!

Official Developer/Creator:

Bugs: @crypt0s - Twitter

bryanhalf@gmail.com - Email

# USAGE:
node FakeDNS -c Config path -i interface IP address --rebind

read the rules.txt for an example.

# Supported Request Types
- A
- TXT
- AAAA
- PTR
- SOA

# Misc
- Supports DNS Rebinding
- Supports round-robin

# Round-Robin
Round-robin rules are implemented. Every time a client requests a matching rule, FakeDNS will serve out the next IP in the list of IP's provided in the rule.
A list of IP's is comma-separated.

For example:

A robin.net 1.2.3.4,1.1.1.1,2.2.2.2
Is a round-robin rule for robin.net which will serve out responses pointing to 1.2.3.4, 1.1.1.1, and 2.2.2.2, iterating through that order every time a request is made by any client for the robin.net entry.

NOTE : These IP's aren't included as a list to the client in the response - they still only get just one IP in the response (could change that later)

# DNS Rebinding
FakeDNS supports rebinding rules, which basically means that the server accepts a certain number of requests from a client for a domain until a threshold (default 1 request) and then it changes the IP address to a different one.

For example:

A rebind.net 1.1.1.1 10%4.5.6.7
Means that we have an A record for rebind.net which evaluates to 1.1.1.1 for the first 10 tries. On the 11th request from a client which has already made 10 requests, FakeDNS starts serving out the second ip, 4.5.6.7

You can use a list of addresses here and FakeDNS will round-robin them for you, just like in the "regular" rule.

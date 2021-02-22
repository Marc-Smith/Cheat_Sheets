##Monitor HTTP traffic on wlan0
tcpdump -i wlan0 -A port http

##Capture credentials on http
tcpdump -i wlan0 -A port http | egrep -i ‘pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user | uname= ‘

##Capture credentials on all protocols
tcpdump -i wlan0 -A port port http or port ftp or port smtp or port imap or port pop3 | egrep -i ‘pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user | uname= ‘

##See what traffic is hitting you
tcpdump -i wlan0 -n  | head

##Find all HOST headers
tcpdump -s0 -vv | grep "Host:"

##Find cookies in all HTTP requests which are being captured
tcpdump -s0 -vv | grep "[Set-Cookie| Host: | Cookie:]"


Skip to content
Search or jump to…

Pull requests
Issues
Marketplace
Explore
 
@Marc-Smith 
SergK
/
cheatsheat-tcpdump
1
5422
Code
Issues
Pull requests
Actions
Projects
Wiki
Security
Insights
cheatsheat-tcpdump/tcpdump_advanced_filters.txt
@SergK
SergK Added recepts from Sebastien Wains
Latest commit d7df7e5 on Aug 8, 2014
 History
 1 contributor
603 lines (416 sloc)  19.9 KB
  
tcpdump advanced filters
========================

Sebastien Wains <sebastien -the at sign- wains -dot- be>
http://www.wains.be

$Id: tcpdump_advanced_filters.txt 36 2013-06-16 13:05:04Z sw $


Notes :

Basic syntax :
==============

Filtering hosts :
-----------------

- Match any traffic involving 192.168.1.1 as destination or source
# tcpdump -i eth1 host 192.168.1.1

- As soure only
# tcpdump -i eth1 src host 192.168.1.1

- As destination only
# tcpdump -i eth1 dst host 192.168.1.1


Filtering ports :
-----------------

- Match any traffic involving port 25 as source or destination
# tcpdump -i eth1 port 25

- Source
# tcpdump -i eth1 src port 25

- Destination
# tcpdump -i eth1 dst port 25


Network filtering :
-------------------

# tcpdump -i eth1 net 192.168
# tcpdump -i eth1 src net 192.168
# tcpdump -i eth1 dst net 192.168


Protocol filtering :
--------------------

# tcpdump -i eth1 arp
# tcpdump -i eth1 ip

# tcpdump -i eth1 tcp
# tcpdump -i eth1 udp
# tcpdump -i eth1 icmp


Let's combine expressions :
---------------------------

Negation    : ! or "not" (without the quotes)
Concatanate : && or "and"
Alternate   : || or "or" 

- This rule will match any TCP traffic on port 80 (web) with 192.168.1.254 or 192.168.1.200 as destination host
# tcpdump -i eth1 '((tcp) and (port 80) and ((dst host 192.168.1.254) or (dst host 192.168.1.200)))'

- Will match any ICMP traffic involving the destination with physical/MAC address 00:01:02:03:04:05
# tcpdump -i eth1 '((icmp) and ((ether dst host 00:01:02:03:04:05)))'

- Will match any traffic for the destination network 192.168 except destination host 192.168.1.200
# tcpdump -i eth1 '((tcp) and ((dst net 192.168) and (not dst host 192.168.1.200)))'


Advanced header filtering :
===========================

Before we continue, we need to know how to filter out info from headers

proto[x:y] 		: will start filtering from byte x for y bytes. ip[2:2] would filter bytes 3 and 4 (first byte begins by 0)
proto[x:y] & z = 0 	: will match bits set to 0 when applying mask z to proto[x:y]
proto[x:y] & z !=0 	: some bits are set when applying mask z to proto[x:y]
proto[x:y] & z = z 	: every bits are set to z when applying mask z to proto[x:y]
proto[x:y] = z 		: p[x:y] has exactly the bits set to z


Operators : >, <, >=, <=, =, !=


This may not be clear in the first place but you'll find examples below involving these.


Of course, it is important to know what the protocol headers look like before diving into more advanced filters.


IP header
---------

	0                   1                   2                   3   
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|Version|  IHL  |Type of Service|          Total Length         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Identification        |Flags|      Fragment Offset    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Time to Live |    Protocol   |         Header Checksum       |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                       Source Address                          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                    Destination Address                        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                    Options                    |    Padding    | <-- optional
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                            DATA ...                           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

I'll consider we are only working with the IPv4 protocol suite for these examples.

In an ideal world, every field would fit inside one byte. This is not the case, of course.

Are IP options set ?
--------------------

Let's say we want to know if the IP header has options set. We can't just try to filter out the 21st byte
because if no options are set, data start at the 21st byte. We know a "normal" header is usually 20 bytes 
(160 bits) long. With options set, the header is longer than that. The IP header has the header 
length field which we will filter here to know if the header is longer than 20 bytes.

	+-+-+-+-+-+-+-+-+
	|Version|  IHL  |
	+-+-+-+-+-+-+-+-+

Usually the first byte has a value of 01000101 in binary.

Anyhow, we need to divide the first byte in half...

0100 = 4 in decimal. This is the IP version.
0101 = 5 in decimal. This is the number of blocks of 32 bits in the headers. 5 x 32 bits = 160 bits or 20 bytes.

The second half of the first byte would be bigger than 5 if the header had IP options set.

We have two ways of dealing with that kind of filters.

1. Either try to match a value bigger than 01000101. This would trigger matches for IPv4 traffic with IP options set, 
   but ALSO any IPv6 traffic !

In decimal 01000101 equals 69.

Let's recap how to calculate in decimal.

0 : 0		\
1 : 2^6 = 64	 \ First field (IP version)
0 : 0		 /
0 : 0		/
-
0 : 0		\
1 : 2^2 = 4	 \ Second field (Header length)
0 : 0		 /
1 : 2^0 = 1	/

64 + 4 + 1 = 69

The first field in the IP header would usually have a decimal value of 69.
If we had IP options set, we would probably have 01000110 (IPv4 = 4 + header = 6), which in decimal equals 70.

This rule should do the job :
# tcpdump -i eth1 'ip[0] > 69'

Somehow, the proper way is to mask the first half/field of the first byte, because as mentionned earlier, 
this filter would match any IPv6 traffic.

2. The proper/right way : "masking" the first half of the byte

0100 0101 : 1st byte originally
0000 1111 : mask (0xf in hex or 15 in decimal). 0 will mask the values while 1 will keep the values intact.
=========
0000 0101 : final result

You should see the mask as a power switch. 1 means on/enabled, 0 means off/disabled.

The correct filter :

In binary
# tcpdump -i eth1 'ip[0] & 15 > 5'

or 

In hexadecimal
# tcpdump -i eth1 'ip[0] & 0xf > 5'

I use hex masks.

Recap.. That's rather simple, if you want to :
- keep the last 4 bits intact, use 0xf (binary 00001111)
- keep the first 4 bits intact, use 0xf0 (binary 11110000)


DF bit (don't fragment) set ?
-----------------------------

Let's now trying to know if we have fragmentation occuring, which is not desirable. Fragmentation occurs 
when a the MTU of the sender is bigger than the path MTU on the path to destination.

Fragmentation info can be found in the 7th and 8th byte of the IP header.

	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|Flags|      Fragment Offset    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Bit 0: 	reserved, must be zero
Bit 1: 	(DF) 0 = May Fragment, 1 = Don't Fragment.
Bit 2: 	(MF) 0 = Last Fragment, 1 = More Fragments.

The fragment offset field is only used when fragmentation occurs.

If we want to match the DF bit (don't fragment bit, to avoid IP fragmentation) :

The 7th byte would have a value of :
01000000 or 64 in decimal

# tcpdump -i eth1 'ip[6] = 64'


Matching fragmentation ?
------------------------

- Matching MF (more fragment set) ? This would match the fragmented datagrams but wouldn't match the last 
  fragment (which has the 2nd bit set to 0).
# tcpdump -i eth1 'ip[6] = 32'

The last fragment have the first 3 bits set to 0... but has data in the fragment offset field.

- Matching the fragments and the last fragments
# tcpdump -i eth1 '((ip[6:2] > 0) and (not ip[6] = 64))'

A bit of explanations :
"ip[6:2] > 0" would return anything with a value of at least 1
We don't want datagrams with the DF bit set though.. the reason of the "not ip[6] = 64"

If you want to test fragmentation use something like :
ping -M want -s 3000 192.168.1.1


Matching datagrams with low TTL
-------------------------------

The TTL field is located in the 9th byte and fits perfectly into 1 byte.
The maximum decimal value of the TTL field is thus 255 (11111111 in binary).

This can be verified :
$ ping -M want -s 3000 -t 256 192.168.1.200
ping: ttl 256 out of range

	+-+-+-+-+-+-+-+-+
	|  Time to Live |
	+-+-+-+-+-+-+-+-+

We can try to find if someone on our network is using traceroute by using something like this on the gateway :
# tcpdump -i eth1 'ip[8] < 5'


Matching packets longer than X bytes
------------------------------------

Where X is 600 bytes

# tcpdump -i eth1 'ip[2:2] > 600'


More IP filtering
-----------------

We could imagine filtering source and destination addresses directly in decimal addressing.
We could also match the protocol by filtering the 10th byte.

It would be pointless anyhow, because tcpdump makes it already easy to filter out that kind of info.


TCP header
----------

	0                   1                   2                   3   
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Source Port          |       Destination Port        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                        Sequence Number                        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                    Acknowledgment Number                      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Data |       |C|E|U|A|P|R|S|F|                               |
	| Offset|  Res. |W|C|R|C|S|S|Y|I|            Window             | 
	|       |       |R|E|G|K|H|T|N|N|                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|           Checksum            |         Urgent Pointer        |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                    Options                    |    Padding    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                             data                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

- Matching any TCP traffic with a source port > 1024
# tcpdump -i eth1 'tcp[0:2] > 1024'

- Matching TCP traffic with particular flag combinations

The flags are defined in the 14th byte of the TCP header.

	+-+-+-+-+-+-+-+-+
	|C|E|U|A|P|R|S|F|
	|W|C|R|C|S|S|Y|I|
	|R|E|G|K|H|T|N|N|
	+-+-+-+-+-+-+-+-+

In the TCP 3-way handshakes, the exchange between hosts goes like this :

1. Source sends SYN 
2. Destination answers with SYN, ACK 
3. Source sends ACK

- If we want to match packets with only the SYN flag set, the 14th byte would have a binary 
  value of 00000010 which equals 2 in decimal.
# tcpdump -i eth1 'tcp[13] = 2'

- Matching SYN, ACK (00010010 or 18 in decimal)
# tcpdump -i eth1 'tcp[13] = 18'

- Matching either SYN only or SYN-ACK datagrams
# tcpdump -i eth1 'tcp[13] & 2 = 2'

We used a mask here. It will returns anything with the ACK bit set (thus the SYN-ACK combination as well)

Let's assume the following examples (SYN-ACK)

00010010 : SYN-ACK packet
00000010 : mask (2 in decimal)
--------
00000010 : result (2 in decimal)

Every bits of the mask match !

- Matching PSH-ACK packets
# tcpdump -i eth1 'tcp[13] = 24'

- Matching any combination containing FIN (FIN usually always comes with an ACK so we either 
  need to use a mask or match the combination ACK-FIN)
# tcpdump -i eth1 'tcp[13] & 1 = 1'

- Matching RST flag
# tcpdump -i eth1 'tcp[13] & 4 = 4'

Actually, there's an easier way to filter flags :
# tcpdump -i eth1 'tcp[tcpflags] == tcp-ack'

- Matching all packages with TCP-SYN or TCP-FIN set : 
# tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0


By looking at the TCP state machine diagram (http://www.wains.be/pub/networking/tcp_state_machine.jpg)
we can find the different flag combinations we may want to analyze.

Ideally, a socket in ACK_WAIT mode should not have to send a RST. It means the 3 way handshake has not completed.
We may want to analyze that kind of traffic.


Matching SMTP data :
--------------------

I will make a filter that will match any packet containing the "MAIL" command from SMTP exchanges.

I use something like http://www.easycalculation.com/ascii-hex.php to convert values from ASCII to hexadecimal.

"MAIL" in hex is 0x4d41494c

The rule would be :

# tcpdump -i eth1 '((port 25) and (tcp[20:4] = 0x4d41494c))'

It will check the bytes 21 to 24. "MAIL" is 4 bytes/32 bits long.. 

This rule would not match packets with IP options set.

This is an example of packet (a spam, of course) :

# tshark -V -i eth0 '((port 25) and (tcp[20:4] = 0x4d41494c))'
Capturing on eth0
Frame 1 (92 bytes on wire, 92 bytes captured)
    Arrival Time: Sep 25, 2007 00:06:10.875424000
    [Time delta from previous packet: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Packet Length: 92 bytes
    Capture Length: 92 bytes
    [Frame is marked: False]
    [Protocols in frame: eth:ip:tcp:smtp]
Ethernet II, Src: Cisco_X (00:11:5c:X), Dst: 3Com_X (00:04:75:X)
    Destination: 3Com_X (00:04:75:X)
        Address: 3Com_X (00:04:75:X)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
    Source: Cisco_X (00:11:5c:X)
        Address: Cisco_X (00:11:5c:X)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
    Type: IP (0x0800)
Internet Protocol, Src: 62.163.X (62.163.X), Dst: 192.168.X (192.168.X)
    Version: 4
    Header length: 20 bytes
    Differentiated Services Field: 0x00 (DSCP 0x00: Default; ECN: 0x00)
        0000 00.. = Differentiated Services Codepoint: Default (0x00)
        .... ..0. = ECN-Capable Transport (ECT): 0
        .... ...0 = ECN-CE: 0
    Total Length: 78
    Identification: 0x4078 (16504)
    Flags: 0x04 (Don't Fragment)
        0... = Reserved bit: Not set
        .1.. = Don't fragment: Set
        ..0. = More fragments: Not set
    Fragment offset: 0
    Time to live: 118
    Protocol: TCP (0x06)
    Header checksum: 0x08cb [correct]
        [Good: True]
        [Bad : False]
    Source: 62.163.X (62.163.X)
    Destination: 192.168.X (192.168.XX)
Transmission Control Protocol, Src Port: 4760 (4760), Dst Port: smtp (25), Seq: 0, Ack: 0, Len: 38
    Source port: 4760 (4760)
    Destination port: smtp (25)
    Sequence number: 0    (relative sequence number)
    [Next sequence number: 38    (relative sequence number)]
    Acknowledgement number: 0    (relative ack number)
    Header length: 20 bytes
    Flags: 0x18 (PSH, ACK)
        0... .... = Congestion Window Reduced (CWR): Not set
        .0.. .... = ECN-Echo: Not set
        ..0. .... = Urgent: Not set
        ...1 .... = Acknowledgment: Set
        .... 1... = Push: Set
        .... .0.. = Reset: Not set
        .... ..0. = Syn: Not set
        .... ...0 = Fin: Not set
    Window size: 17375
    Checksum: 0x6320 [correct]
        [Good Checksum: True]
        [Bad Checksum: False]
Simple Mail Transfer Protocol
    Command: MAIL FROM:<wguthrie_at_mysickworld--dot--com>\r\n
        Command: MAIL
        Request parameter: FROM:<wguthrie_at_mysickworld--dot--com>


Matching HTTP data :
--------------------

Let's make a filter that will find any packets containing GET requests
The HTTP request will begin by :

GET / HTTP/1.1\r\n (16 bytes counting the carriage return but not the backslashes !)

If no IP options are set.. the GET command will use the byte 20, 21 and 22
Usually, options will take 12 bytes (12nd byte indicates the header length, which should report 32 bytes). 
So we should match bytes 32, 33 and 34 (1st byte = byte 0).

Tcpdump is only able to match data size of either 1, 2 or 4 bytes, we will take the following ASCII 
character following the GET command (a space)

"GET " in hex : 47455420
 
# tcpdump -i eth1 'tcp[32:4] = 0x47455420'


Matching HTTP data (exemple taken from tcpdump man page) : 

# tcpdump -i eth1 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
ip[2:2] = |          Total Length         |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	+-+-+-+-+-+-+-+-+
ip[0] =	|Version|  IHL  |
	+-+-+-+-+-+-+-+-+

	     +-+-+-+-+-+-+-+-+
ip[0]&0xf =  |# # # #|  IHL  | <-- that's right, we masked the version bits with 0xf or 00001111 in binary
	     +-+-+-+-+-+-+-+-+

          +-+-+-+-+
	  |  Data |
tcp[12] = | Offset|
	  |       |
	  +-+-+-+-+

So what we are doing here is "(IP total length - IP header length - TCP header length) != 0"

We are matching any packet that contains data.


We are taking the IHL (total IP lenght


Matching other interesting TCP things :
---------------------------------------

SSH connection (on any port) : 
We will be looking for the reply given by the SSH server.
OpenSSH usually replies with something like "SSH-2.0-OpenSSH_3.6.1p2".
The first 4 bytes (SSH-) have an hex value of 0x5353482D.

# tcpdump -i eth1 'tcp[(tcp[12]>>2):4] = 0x5353482D'

If we want to find any connection made to older version of OpenSSH (version 1, which are insecure and subject to MITM attacks) : 
The reply from the server would be something like "SSH-1.99.."

# tcpdump -i eth1 '(tcp[(tcp[12]>>2):4] = 0x5353482D) and (tcp[((tcp[12]>>2)+4):2] = 0x312E)'

Explanation of >>2 can be found below in the reference section.


UDP header
----------

  0      7 8     15 16    23 24    31  
 +--------+--------+--------+--------+ 
 |     Source      |   Destination   | 
 |      Port       |      Port       | 
 +--------+--------+--------+--------+ 
 |                 |                 | 
 |     Length      |    Checksum     | 
 +--------+--------+--------+--------+ 
 |                                   | 
 |              DATA ...             |
 +-----------------------------------+                 

Nothing really interesting here.

If we want to filter ports we would use something like :
# tcpdump -i eth1 udp dst port 53


ICMP header
-----------

See different ICMP messages :
http://img292.imageshack.us/my.php?image=icmpmm6.gif

We will usually filter the type (1 byte) and code (1 byte) of the ICMP messages.

Here are common ICMP types :

  0	Echo Reply				 [RFC792]
  3	Destination Unreachable			 [RFC792]
  4	Source Quench			 	 [RFC792]
  5	Redirect				 [RFC792]
  8	Echo					 [RFC792]
 11	Time Exceeded				 [RFC792]

We may want to filter ICMP messages type 4, these kind of messages are sent in case of congestion of the network.
# tcpdump -i eth1 'icmp[0] = 4'


If we want to find the ICMP echo replies only, having an ID of 500. By looking at the image with all the ICMP packet description
we see the ICMP echo reply have the ID spread across the 5th and 6th byte. For some reason, we have to filter out with the value in hex.

# tcpdump -i eth0 '(icmp[0] = 0) and (icmp[4:2] = 0x1f4)'


References
----------

tcpdump man page : http://www.tcpdump.org/tcpdump_man.html
Conversions : http://easycalculation.com/hex-converter.php
Filtering HTTP requests : http://www.wireshark.org/tools/string-cf.html
Filtering data regardless of TCP options : http://www.wireshark.org/lists/wireshark-users/201003/msg00024.html

Just in case the post disappears, here's a copy of the last URL :

From: Sake Blok <sake@xxxxxxxxxx>
Date: Wed, 3 Mar 2010 22:42:29 +0100
Or if your capturing device is capable of interpreting tcpdump style filters (or more accurately, BPF style filters), you could use:

tcp[(((tcp[12:1] & 0xf0) >> 2) + 8):2] = 0x2030

Which in English would be: 
- take the upper 4 bits of the 12th octet in the tcp header ( tcp[12:1] & 0xf0 )
- multiply it by four ( (tcp[12:1] & 0xf0)>>2 ) which should give the tcp header length
- add 8 ( ((tcp[12:1] & 0xf0) >> 2) + 8 ) gives the offset into the tcp header of the space before the first octet of the response code
- now take two octets from the tcp stream, starting at that offset ( tcp[(((tcp[12:1] & 0xf0) >> 2) + 8):2]  )
- and verify that they are " 0" ( = 0x2030 )

Of course this can give you false positives, so you might want to add a test for "HTTP" and the start of the tcp payload with:

tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450

resulting in the filter:

tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450 and tcp[(((tcp[12:1] & 0xf0) >> 2) + 8):2] = 0x2030

A bit cryptic, but it works, even when TCP options are present (which would mess up a fixed offset into the tcp data).

© 2021 GitHub, Inc.
Terms
Privacy
Security
Status
Docs
Contact GitHub
Pricing
API
Training
Blog
About


# [TCPDUMP](https://wuseman.github.io/TCPDUMP/)


## README

Tcpdump is one of the best network analysis-tools ever for information security professionals. 
Tcpdump is for everyone for hackers and people who have less of TCP/IP understanding. 

Many prefer to use higher-level analysis tools such Wireshark, _but I believe it is a mistake_. 

## OPTIONS

#### Below are some tcpdump options (with useful examples) that will help you working with the tool. They’re very easy to forget and/or confuse with other types of filters, i.e. ethereal, so hopefully this article can serve as a reference for you, as it does me:)

* The first of these is -n, which requests that names are not resolved, resulting in the IPs themselves.
* The second is -X, which displays both hex and ascii content within the packet.
* The final one is -S, which changes the display of sequence numbers to absolute rather than relative.

### Show the packet’s contents in both hex and ascii.   

    tcpdump -X ....         
      
### Same as -X, but also shows the ethernet header.
  
    tcpdump -XX

###  Show the list of available interfaces

    tcpdump -D

### Line-readable output (for viewing as you save, or sending to other commands)

    tcpdump -l

### Be less verbose (more quiet) with your output.

    tcpdump -q

### Give human-readable timestamp output.

    tcpdump -t :

### Give maximally human-readable timestamp output.

    tcpdump -tttt : 

### Listen on the eth0 interface.

    tcpdump -i eth0

### Verbose output (more v’s gives more output).

    tcpdump -vv 

### Only get x number of packets and then stop.
  
    tcpdump -c 

### Define the snaplength (size) of the capture in bytes. Use -s0 to get everything, unless you are intentionally capturing less.

    tcpdump -s 

### Print absolute sequence numbers.
  
    tcpdump -S 

### Get the ethernet header as well.
    
    tcpdump -e 

### Decrypt IPSEC traffic by providing an encryption key.
    
    tcpdump -E

### For more options, read manual:

* Find all options [here](https://www.cyberciti.biz/howto/question/man/tcpdump-man-page-with-examples.php)

# BASIC USAGE

###  Display Available Interfaces

    tcpdump -D
    tcpdump --list-interfaces
   
### Let’s start with a basic command that will get us HTTPS traffic:

    tcpdump -nnSX port 443

### Find Traffic by IP

    tcpdump host 1.1.1.1

### Filtering by Source and/or Destination

    tcpdump src 1.1.1.1 
    tcpdump dst 1.0.0.1

### Finding Packets by Network
    
    tcpdump net 1.2.3.0/24

#### Low Output: 

    tcpdump -nnvvS

#### Medium Output: 

    tcpdump -nnvvXS

#### Heavy Output:

    tcpdump -nnvvXSs 1514


# Getting Creative

* Expressions are very nice, but the real magic of tcpdump comes from the ability to combine them in creative ways in order to isolate exactly what you’re looking for. 

## There are three ways to do combination:

### AND

    and or &&

### OR

    or or ||

### EXCEPT
    
    not or !

# Usage Example: 

### Traffic that’s from 192.168.1.1 AND destined for ports 3389 or 22
    
    tcpdump 'src 192.168.1.1 and (dst port 3389 or 22)'


# Advanced 

### Show me all URG packets:
    
    tcpdump 'tcp[13] & 32 != 0'

### Show me all ACK packets:

    tcpdump 'tcp[13] & 16 != 0'

### Show me all PSH packets:
    
    tcpdump 'tcp[13] & 8 != 0'

### Show me all RST packets:

    tcpdump 'tcp[13] & 4 != 0'

### Show me all SYN packets:

    tcpdump 'tcp[13] & 2 != 0'

### Show me all FIN packets:

    tcpdump 'tcp[13] & 1 != 0'

### Show me all SYN-ACK packets:
    
    tcpdump 'tcp[13] = 18'

### Show all traffic with both SYN and RST flags set: (that should never happen)

    tcpdump 'tcp[13] = 6'

### Show all traffic with the “evil bit” set:

    tcpdump 'ip[6] & 128 != 0'

### Display all IPv6 Traffic:

    tcpdump ip6

### Print Captured Packets in ASCII

    tcpdump -A -i eth0

### Display Captured Packets in HEX and ASCII
    
    tcpdump -XX -i eth0

### Capture and Save Packets in a File

    tcpdump -w 0001.pcap -i eth0

### Read Captured Packets File

    tcpdump -r 0001.pcap

### Capture IP address Packets

    tcpdump -n -i eth0

### Capture only TCP Packets.

    tcpdump -i eth0 tcp

### Capture Packet from Specific Port

    tcpdump -i eth0 port 22

### Capture Packets from source IP
    
    tcpdump -i eth0 src 192.168.0.2

### Capture Packets from destination IP

    tcpdump -i eth0 dst 50.116.66.139

### Capture any packed coming from x.x.x.x

    tcpdump -n src host x.x.x.x

### Capture any packet coming from or going to x.x.x.x
    
    tcpdump -n host x.x.x.x

### Capture any packet going to x.x.x.x

    tcpdump -n dst host x.x.x.x

### Capture any packed coming from x.x.x.x
    
    tcpdump -n src host x.x.x.x

### Capture any packet going to network x.x.x.0/24

    tcpdump -n dst net x.x.x.0/24

### Capture any packet coming from network x.x.x.0/24

    tcpdump -n src net x.x.x.0/24

### Capture any packet with destination port x

    tcpdump -n dst port x

### Capture any packet coming from port x
    
    tcpdump -n src port x

### Capture any packets from or to port range x to y

    tcpdump -n dst(or src) portrange x-y

### Capture any tcp or udp port range x to y

    tcpdump -n tcp(or udp) dst(or src) portrange x-y

### Capture any packets with dst ip x.x.x.x and port y
    
    tcpdump -n "dst host x.x.x.x and dst port y"

### Capture any packets with dst ip x.x.x.x and dst ports x, z

    tcpdump -n "dst host x.x.x.x and (dst port x or dst port z)"

### Capture ICMP , ARP

    tcpdump -v icmp(or arp)

### Capture packets on interface eth0 and dump to cap.txt file

    tcpdump -i eth0 -w cap.txt

### Get Packet Contents with Hex Output

    tcpdump -c 1 -X icmp

### Show Traffic Related to a Specific Port
    
    tcpdump port 3389 
    tcpdump src port 1025

### Show Traffic of One Protocol
    
    tcpdump icmp

### Find Traffic by IP

    tcpdump host 1.1.1.1

### Filtering by Source and/or Destination

    tcpdump src 1.1.1.1 
    tcpdump dst 1.0.0.1

### Finding Packets by Network
    
    tcpdump net 1.2.3.0/24


### Get Packet Contents with Hex Output
   
    tcpdump -c 1 -X icmp

### Show Traffic Related to a Specific Port

    tcpdump port 3389 
    tcpdump src port 1025

### Show Traffic of One Protocol

    tcpdump icmp

### Show only IP6 Traffic

    tcpdump ip6

### Find Traffic Using Port Ranges

    tcpdump portrange 21-23

### Find Traffic Based on Packet Size

     tcpdump less 32 
     tcpdump greater 64 
     tcpdump <= 128
     tcpdump => 128

### Reading / Writing Captures to a File (pcap)
    
    tcpdump port 80 -w capture_file
    tcpdump -r capture_file


# It’s All About the Combinations

### Raw Output View

    tcpdump -ttnnvvS

## Here are some examples of combined commands.

### From specific IP and destined for a specific Port

    tcpdump -nnvvS src 10.5.2.3 and dst port 3389

### From One Network to Another

    tcpdump -nvX src net 192.168.0.0/16 and dst net 10.0.0.0/8 or 172.16.0.0/16

### Non ICMP Traffic Going to a Specific IP
    
    tcpdump dst 192.168.0.2 and src net and not icmp

### Traffic From a Host That Isn’t on a Specific Port
    
    tcpdump -vv src mars and not dst port 22

### Isolate TCP RST flags.

    tcpdump 'tcp[13] & 4!=0'
    tcpdump 'tcp[tcpflags] == tcp-rst'

### Isolate TCP SYN flags.

    tcpdump 'tcp[13] & 2!=0'
    tcpdump 'tcp[tcpflags] == tcp-syn'

### Isolate packets that have both the SYN and ACK flags set.

    tcpdump 'tcp[13]=18'

### Isolate TCP URG flags.

    tcpdump 'tcp[13] & 32!=0'
    tcpdump 'tcp[tcpflags] == tcp-urg'

### Isolate TCP ACK flags.

    tcpdump 'tcp[13] & 16!=0'
    tcpdump 'tcp[tcpflags] == tcp-ack'

### Isolate TCP PSH flags.

    tcpdump 'tcp[13] & 8!=0'
    tcpdump 'tcp[tcpflags] == tcp-psh'

### Isolate TCP FIN flags.

    tcpdump 'tcp[13] & 1!=0'
    tcpdump 'tcp[tcpflags] == tcp-fin'

# Commands that I using almost daily

### Both SYN and RST Set

    tcpdump 'tcp[13] = 6'

### Find HTTP User Agents

    tcpdump -vvAls0 | grep 'User-Agent:'
    tcpdump -nn -A -s1500 -l | grep "User-Agent:"

### By using egrep and multiple matches we can get the User Agent and the Host (or any other header) from the request.
    
    tcpdump -nn -A -s1500 -l | egrep -i 'User-Agent:|Host:'

### Capture only HTTP GET and POST packets only packets that match GET.
    tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'
    tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354'

### Extract HTTP Request URL's
    
    tcpdump -s 0 -v -n -l | egrep -i "POST /|GET /|Host:"

### Extract HTTP Passwords in POST Requests
    
    tcpdump -s 0 -A -n -l | egrep -i "POST /|pwd=|passwd=|password=|Host:"

### Capture Cookies from Server and from Client
    
    tcpdump -nn -A -s0 -l | egrep -i 'Set-Cookie|Host:|Cookie:'

### Capture all ICMP packets
    
    tcpdump -n icmp

### Show ICMP Packets that are not ECHO/REPLY (standard ping)
    
    tcpdump 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply'

### Capture SMTP / POP3 Email
    
    tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'

### Troubleshooting NTP Query and Response
    
    tcpdump dst port 123

### Capture FTP Credentials and Commands
    
    tcpdump -nn -v port ftp or ftp-data

### Rotate Capture Files
    
    tcpdump  -w /tmp/capture-%H.pcap -G 3600 -C 200

### Capture IPv6 Traffic
    
    tcpdump -nn ip6 proto 6

### IPv6 with UDP and reading from a previously saved capture file.
    
    tcpdump -nr ipv6-test.pcap ip6 proto 17

### Detect Port Scan in Network Traffic
    
    tcpdump -nn

# USAGE EXAMPLE

### Example Filter Showing Nmap NSE Script Testing
  
* On Target: 

      nmap -p 80 --script=http-enum.nse targetip

* On Server:  

      tcpdump -nn port 80 | grep "GET /"
        
           GET /w3perl/ HTTP/1.1
           GET /w-agora/ HTTP/1.1
           GET /way-board/ HTTP/1.1
           GET /web800fo/ HTTP/1.1
           GET /webaccess/ HTTP/1.1
           GET /webadmin/ HTTP/1.1
           GET /webAdmin/ HTTP/1.1

### Capture Start and End Packets of every non-local host
    
    tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet'

### Capture DNS Request and Response
    
    tcpdump -i wlp58s0 -s0 port 53

### Capture HTTP data packets
    
    tcpdump 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

### Capture with tcpdump and view in Wireshark
    
    ssh wuseman@localhost 'tcpdump -s0 -c 1000 -nn -w - not port 22' | wireshark -k -i -

### Top Hosts by Packets
    
    tcpdump -nnn -t -c 200 | cut -f 1,2,3,4 -d '.' | sort | uniq -c | sort -nr | head -n 20

### Capture all the plaintext passwords
    
    tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '

    tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -lA | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd= |password=|pass:|user:|username:|password:|login:|pass |user '

### DHCP Example

    tcpdump -v -n port 67 or 68

### Cleartext GET Requests

    tcpdump -vvAls0 | grep 'GET'

### Find HTTP Host Headers

    tcpdump -vvAls0 | grep 'Host:'

### Find HTTP Cookies

    tcpdump -vvAls0 | grep 'Set-Cookie|Host:|Cookie:'

### Find SSH Connections
    
    tcpdump 'tcp[(tcp[12]>>2):4] = 0x5353482D'

### Find DNS Traffic
    
    tcpdump -vvAs0 port 53

### Find FTP Traffic
    
    tcpdump -vvAs0 port ftp or ftp-data

### Find NTP Traffic
    
    tcpdump -vvAs0 port 123

### Capture SMTP / POP3 Email
    tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'

### Line Buffered Mode

    tcpdump -i eth0 -s0 -l port 80 | grep 'Server:'

### Find traffic with evil bit

    tcpdump 'ip[6] & 128 != 0'

### Filter on protocol (ICMP) and protocol-specific fields (ICMP type)

tcpdump -n icmp and 'icmp[0] != 8 and icmp[0] != 0'

### Same command can be used with predefined header field offset (icmptype) and ICMP type field values (icmp-echo and icmp-echoreply):

    tcpdump -n icmp and icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply

### Filter on TOS field

    tcpdump -v -n ip and ip[1]!=0

### Filter on TTL field

    tcpdump -v ip and 'ip[8]<2'

### Filter on TCP flags (SYN/ACK)

    tcpdump -n tcp and port 80 and 'tcp[tcpflags] & tcp-syn == tcp-syn'

### In the example above, all packets with TCP SYN flag set are captured. Other flags (ACK, for example) might be set also. Packets which have only TCP SYN flags set, can be captured 

    tcpdump tcp and port 80 and 'tcp[tcpflags] == tcp-syn'

### Catch TCP SYN/ACK packets (typically, responses from servers):

    tcpdump -n tcp and 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'
    tcpdump -n tcp and 'tcp[tcpflags] & tcp-syn == tcp-syn' and 'tcp[tcpflags] & tcp-ack == tcp-ack'

### Catch ARP packets

    tcpdump -vv -e -nn ether proto 0x0806

### Filter on IP packet length

    tcpdump -l icmp and '(ip[2:2]>50)' -w - |tcpdump -r - -v ip and '(ip[2:2]<60)'

### Remark: due to some bug in tcpdump, the following command doesn't catch packets as expected:

    tcpdump -v -n icmp and '(ip[2:2]>50)' and '(ip[2:2]<60)'

### Filter on encapsulated content (ICMP within PPPoE)

    tcpdump -v -n icmp

### Queiter

    tcpdump -q -i eth0
    tcpdump -t -i eth0
    tcpdump -A -n -q -i eth0 'port 80'
    tcpdump -A -n -q -t -i eth0 'port 80'

### Print only useful packets from the HTTP traffic
 
    tcpdump -A -s 0 -q -t -i eth0 'port 80 and ( ((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12:2]&0xf0)>>2)) != 0)'

### Dump SIP Traffic

    tcpdump -nq -s 0 -A -vvv port 5060 and host 1.2.3.4

### Checking packet content

    tcpdump -i any -c10 -nn -A port 80

### Checking packet content

    sudo tcpdump -i any -c10 -nn -A port 80

# References & Awesome wikis

* https://hackertarget.com/tcpdump-examples/

* https://wiki.geant.org/display/public/EK/TcpdumpExamples

* http://edoceo.com/cli/tcpdump

* https://www.thegeekstuff.com/2010/08/tcpdump-command-examples/

* https://opensource.com/article/18/10/introduction-tcpdump

#### CONTACT 

If you have problems, questions, ideas or suggestions please contact
us by posting to wuseman@nr1.nu

#### WEB SITE

Visit our homepage for the latest info and updated tools

https://nr1.nu & https://github.com/wuseman/

#### END!




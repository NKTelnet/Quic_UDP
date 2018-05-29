#Quic_UDP

This is a Linux Kernel module for quick UDP 5 tuples connection lookup.

The current code is written for Linux Kernel 3.10.x now.

To compile the code to a Linux Kernel module:
1. Change the KDIR of the Makefile to the real directory that 3.10.x Linux Kernel Source code is in.
2. Run command "make" to generate a Kernel module file named "crystal.ko"

Once we get the file "cyrstal.ko", we can run command "insmod ./crystal.ko" to load this module to Kernel. Then we can use command "dmesg" to check whether this module is loaded to Kernel successfully or not. 

Now we can use the following code to enable the quick UDP 5 tuples connection lookup feature in the UPD programs:

sock = socket(PF_INET, SOCK_DGRAM, 0);

int optval = 1;
setsockopt(sock, SOL_UDP, 200, &optval, sizeof(optval));

bind(...); // this is not necessary

connect(...);

#  iSCSI length constraints vulnerability in the Linux kernel

### Introduction

Barely a month ago, from the 5.11.3 release version of Linux kernel had been discoverd a vulnerability called **Linux Kernel Heap Buffer Overflow**. The CVE code indicated this vulnerbility is **CVE-2021-27365**.

-----

The statement of this exploit declear that certain iSCSI data structures do not have appropriate length constraints set up, which can cause the PAGE_SIZE value in the structures exceed the limit and lead to buffer overflow. 
iSCSI is a transport layer protocol that provides block-level access to storage devices by carrying SCSI commands over a TCP/IP network.



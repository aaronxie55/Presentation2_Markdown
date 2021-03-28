#  iSCSI length constraints vulnerability in the Linux kernel

### Introduction

Barely a month ago, from the 5.11.3 release version of Linux kernel had been discoverd a vulnerability called **Linux Kernel Heap Buffer Overflow**. The CVE code indicated this vulnerbility is **CVE-2021-27365**.

+ **Type of Vulnerability:** Heap Buffer Overflow
+ **Where it is found:** iscsi_host_get_param() in drivers/scsi/libiscsi.c
+ **Affected Versions:** Tested on RHEL 8.1, 8.2, and 8.3
+ **Impact:** Privilege escalation, Information Leak, Denial of Service
+ **CVSS Version 3.x score:** 7.8 (High)
---

The statement of this exploit declear that certain *iSCSI data structures* do not have appropriate length constraints set up, which can cause the *PAGE_SIZE* value in the structures exceed the limit and lead to buffer overflow.

*iSCSI* is a transport layer protocol that provides block-level access to storage devices by carrying SCSI commands over a TCP/IP network.

#### Attack Method
An unauthorised user with this vulnerability can send a pre-adjusted Netlink message that is associated with iSCSI. This Netlink message had been set to the maximum length to causing the heap overflow. Then the attacker would use this to execute an arbitrary code or launch a denial of service attack.

#### Fun Fact
Although the vulnerability was recently discovered, this bug has been present since 2006 when it was first introduced during the development of the iSCSI subsystem.

### Technical Analysis
---

This vulnerability is a heap buffer overflow found in the iSCSI subsystem. The vulnerability is exposed by setting an iSCSI string attribute to a value larger than one page, and then trying to read it.

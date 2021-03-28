#  iSCSI length constraints vulnerability in the Linux kernel

### Introduction

Barely a month ago, from the 5.11.3 release version of Linux kernel had been discoverd a vulnerability called **Linux Kernel Heap Buffer Overflow**. The CVE code indicated this vulnerability is **CVE-2021-27365**.

+ **Type of Vulnerability:** Heap Buffer Overflow
+ **Where it is found:** iscsi_host_get_param() in drivers/scsi/libiscsi.c
+ **Affected Versions:** Tested on RHEL 8.1, 8.2, and 8.3
+ **Impact:** Privilege escalation, Information Leak, Denial of Service
+ **CVSS Version 3.x score:** 7.8 (High)
---

The statement of this vulnerability declares that certain *iSCSI data structures* do not have appropriate length constraints set up, which can cause the *PAGE_SIZE* value in the structures to exceed the limit and lead to a buffer overflow.

*iSCSI* is a transport layer protocol that provides block-level access to storage devices by carrying SCSI commands over a TCP/IP network.

#### Attack Method
An unauthorised user with this vulnerability can send a pre-adjusted Netlink message that is associated with iSCSI. This Netlink message had been set to the maximum length to causing the heap overflow. Then the attacker would use this to execute an arbitrary code or launch a denial of service attack.

#### Fun Fact
Although the vulnerability was recently discovered, this bug has been present since 2006, when it was first introduced during the development of the iSCSI subsystem.

### Technical Analysis

This vulnerability is a heap buffer overflow found in the iSCSI subsystem. The vulnerability is exposed by setting an iSCSI string attribute to a value larger than one page and then trying to read it.

--- 

Examining what the code contains, we see that a **sprintf** call, *a function that assumes an arbitrarily long string*, is used on the user-provided value with a buffer of a single page.  This is used for the seq file, a file that backs the iscsi attribute.

Knowing this vulnerability, an unprivileged user is able to forward Netlink messages to the iSCSI subsystem, which then sets attributes related to the iSCSI connection, such as hostname, username, etc., through the helper functions in *drivers/scsi/libiscsi.c*. The size of the limitation of these attributes is configured only by the maximum length of a Netlink message. Then the *sysfs and seqfs subsystem* will be used to read these attributes. However, it will only distribute a buffer of the *PAGE_SIZE* **(single_open in fs/seq_file.c, called when the sysfs file is opened)**.

![vuln](https://user-images.githubusercontent.com/70997275/112740216-2325da80-8f49-11eb-8dec-510ebd6f1fa1.png)

*Image from the “New Old Bugs in the Linux Kernel” Article on the Grimm blog by Adam March 12, 2021*


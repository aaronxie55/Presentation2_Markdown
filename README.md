#  iSCSI length constraints vulnerability in the Linux kernel
#### By: Brody Massecar, Olatubosun Aremu and Yifeng Xie

## Introduction

Barely a month ago, from the 5.11.3 release version of Linux kernel had been discoverd a vulnerability called **Linux Kernel Heap Buffer Overflow**. The CVE code indicated this vulnerability is **CVE-2021-27365**.

+ **Type of Vulnerability:** Heap Buffer Overflow
+ **Where it is found:** iscsi_host_get_param() in drivers/scsi/libiscsi.c
+ **Affected Versions:** Tested on RHEL 8.1, 8.2, and 8.3
+ **Impact:** Privilege escalation, Information Leak, Denial of Service
+ **CVSS Version 3.x score:** 7.8 (High)

| Overall Score       		| 7.8           |
|:------------------------------|:-------------:|
| Base Score       		| 7.8           |
| Impact subscore 		| 5.9           |
| Exploitability subscore       | 1.8           |


---

The statement of this vulnerability declares that certain *iSCSI data structures* do not have appropriate length constraints set up, which can cause the *PAGE_SIZE* value in the structures to exceed the limit and lead to a buffer overflow.

*iSCSI* is a transport layer protocol that provides block-level access to storage devices by carrying SCSI commands over a TCP/IP network.

#### Attack Method
An unauthorised user with this vulnerability can send a pre-adjusted Netlink message that is associated with iSCSI. This Netlink message had been set to the maximum length to causing the heap overflow. Then the attacker would use this to execute an arbitrary code or launch a denial of service attack.

#### Fun Fact
Although the vulnerability was recently discovered, this bug has been present since 2006, when it was first introduced during the development of the iSCSI subsystem.

## Technical Analysis

This vulnerability is a heap buffer overflow found in the iSCSI subsystem. The vulnerability is exposed by setting an iSCSI string attribute to a value larger than one page and then trying to read it.

--- 

Examining what the code contains, we see that a **sprintf** call, *a function that assumes an arbitrarily long string*, is used on the user-provided value with a buffer of a single page.  This is used for the seq file, a file that backs the iscsi attribute.

Knowing this vulnerability, an unprivileged user is able to forward Netlink messages to the iSCSI subsystem, which then sets attributes related to the iSCSI connection, such as hostname, username, etc., through the helper functions in *drivers/scsi/libiscsi.c*. The size of the limitation of these attributes is configured only by the maximum length of a Netlink message. Then the *sysfs and seqfs subsystem* will be used to read these attributes. However, it will only distribute a buffer of the *PAGE_SIZE* **(single_open in fs/seq_file.c, called when the sysfs file is opened)**.

![vuln](https://user-images.githubusercontent.com/70997275/112740216-2325da80-8f49-11eb-8dec-510ebd6f1fa1.png)

*Image from the “New Old Bugs in the Linux Kernel” Article on the Grimm blog by Adam March 12, 2021*

## Exploit

An exploit was developed by the authors of the Grimm Blog showing the implementation of this vulnerability called [a Proof of Concept (PoC) exploit](https://github.com/grimm-co/NotQuite0DayFriday/tree/trunk/2021.03.12-linux-iscsi) . The exploit was done in conjunction with two other vulnerabilities; **Linux pointer leak to userspace** *(CVE-2021-27363)* & **Linux Kernel Out-of-Bounds Read** *(CVE-2021-27364)*. The following are the different stages of the exploit.

---

**KASLR (Kernel address space layout randomization) Leak**

*KASLR* is how the Linux kernel system randomizes its base address space. To implement this exploit, we must first bypass *KASLR* to gain the privilege to modify kernel structures and to replace function pointers. This bypass is possible due to two information leak that is present in this exploit.

The first information leak is from *a non-null terminated heap buffer*. When the function `iscsi_switch_str_param` setting up an iSCSI string attribute, another function `kstrdup` will be called, and it uses `new_val_buf`, which is a user-provided input.
```c
/*code for function iscsi_switch_str_param*/
int iscsi_switch_str_param(char **param, char *new_val_buf)
{
  char *new_val;
  if (*param) {
    if (!strcmp(*param, new_val_buf))
      return 0;
  } 
  new_val = kstrdup(new_val_buf, GFP_NOIO);
  if (!new_val)
    return -ENOMEM;
  kfree(*param);
  *param = new_val;
  return 0;
}
```
However, when allocated, the buffer that included the user-provided input is not initialized. Moreover, the kernel does not enforce the buffer termination when the user’s input is NULL. It turns out; the `kstrdup` function will take all the non-NULL bytes after the user input. And this value can be retrieved by reading the attribute later.

The exploit uses this information leak by declaring a string of 656 bytes. This string will be store in the address of the `netlink_sock_destruct`, which is a string included in the `kstrdup`.
After setting up the string, the exploit can get the address of `kstrdup` function by reading back the pre-adjusted attribute. 
Then the exploit can calculate the *kernel slide* by subtracting off the base address of the `netlink_sock_destruct`. The allocation will then set the `netlink_sock_destruct` function point to another function `__netlink_create` which is part of sending a Netlink message.
```c
/*code for function int __netlink_create*/
static int __netlink_create(struct net *net, struct socket *sock,
			    struct mutex *cb_mutex, int protocol,
			    int kern)
{
	struct sock *sk;
	struct netlink_sock *nlk;
	sock->ops = &netlink_ops;
	sk = sk_alloc(net, PF_NETLINK, GFP_KERNEL, &netlink_proto, kern);
	if (!sk)
		return -ENOMEM;
	sock_init_data(sock, sk);
	nlk = nlk_sk(sk);
	if (cb_mutex) {
		nlk->cb_mutex = cb_mutex;
	} else {
		nlk->cb_mutex = &nlk->cb_def_mutex;
		mutex_init(nlk->cb_mutex);
		lockdep_set_class_and_name(nlk->cb_mutex,
					   nlk_cb_mutex_keys + protocol,
					   nlk_cb_mutex_key_strings[protocol]);
	}
	init_waitqueue_head(&nlk->wait);
	sk->sk_destruct = netlink_sock_destruct;
	sk->sk_protocol = protocol;
	return 0;
}
```

The second information leak gains the address of the target module’s `iscsi_transport` structure by using the *Linux pointer leak to userspace* vulnerability. The `iscsi_transport` structure is used to define the operations between transportation, like the iSCSI requests. 

Because this `iscsi_transport` structure is in the global region of the target kernel module, the exploit then can use this information leak to get the kernel module's address and the variables in the address. 

----
There are four more steps for the exploit including 
+ Obtaining a Kernel Write Primitive
+ Target Selection and Exploitation
+ Obtaining a Stable Kernel Read/Write Primitive
+ Privilege Escalation

## Impact

As a consequence of heap overflows being inherently non-deterministic, this vulnerability leads to *unreliable, local, Denial of Service attacks*. In the case that the vulnerability is used in conjunction with leaked information, a hacker can use a local privilege escalation to change their access from an unprivileged user to a root user. Furthermore, the vulnerability can be used to leak system kernel memory, even without any sort of information leak. 

---

The bug only affected machines that were running certain operating systems. The flowchart below gives a good representation of which configurations were vulnerable.

![vuln_flowchart](https://user-images.githubusercontent.com/70997275/112741752-499e4280-8f56-11eb-93da-a5e17d24328d.png)

*Image from the “New Old Bugs in the Linux Kernel” Article on the Grimm blog by Adam March 12, 2021*

As shown in the image, the necessary modules for the vulnerability can get loaded onto a machine automatically depending on how the operating system was installed. The bug specifically relied on the `scsi_transport_iscsi` kernel module being loaded, which automatically loaded when a socket call is performed that creates a `NETLINK_ISCSI` socket. Additionally, when an unprivileged user creates a `NETLINK_RDMA` socket, an `ib_iser` transport module is automatically loaded into the ISCSI subsystem -another requirement for the bug.

## Conclusion

While this vulnerability may have been a new issue, the bug has, in fact, existed for several years on an old Linux kernel driver. The driver has become increasingly relevant as new remote direct memory access technology has developed new behaviors involving the kernel. Attackers then took advantage of the Linux kernel automatically loading certain modules, which allowed them to increase the attack surface of the kernel.

There are plenty of ways to against module autoloading, for example, the implementation of *modules_autoload_mode*, the *modules_disabled sysctl variable*, the use of *machine-specific module blacklists*, etc. 

Still, this issue is the problem that currently people are facing in real life. It is hard for the Linux kernel system to be configured as we wanted due to the consideration of compatibility and security. So, the developers and administrators should know the risk and the methods against it in order to protect their system.

## References
1. https://nvd.nist.gov/vuln/detail/CVE-2021-27365
2. Adam. (2021, March 12). New old bugs in the linux kernel. Retrieved March 28, 2021, from https://blog.grimm-co.com/2021/03/new-old-bugs-in-linux-kernel.html
3. Af_Netlink.C - net/netlink/af_netlink.c - linux source code (v5.11.10). (n.d.). Retrieved March 28, 2021, from https://elixir.bootlin.com/linux/latest/source/net/netlink/af_netlink.c
4. Experts found three new 15-year-old bugs in a Linux kernel module. (2021, March 13). Retrieved March 28, 2021, from https://securityaffairs.co/wordpress/115565/security/linux-kernel-flaws.html
5. Kernel/Git/Torvalds/Linux.Git - linux kernel source tree. (n.d.). Retrieved March 28, 2021, from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ec98ea7070e94cc25a422ec97d1421e28d97b7ee
6. Kernel/Git/Torvalds/Linux.Git - linux kernel source tree. (n.d.). Retrieved March 28, 2021, from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f9dbdf97a5bd92b1a49cee3d591b55b11fd7a6d5
7. Oss-Security - linux iscsi security fixes. (n.d.). Retrieved March 28, 2021, from https://www.openwall.com/lists/oss-security/2021/03/06/1

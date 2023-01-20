# gtpuping

An experimental CLI tool to send/receive GTPv1-U packet.

# Usage

```shell
gtpuping -listen-addr 10.0.1.2:2152 \
	-dst-addr 10.0.1.1:2152 \
	-icmp-dst-addr 10.0.2.2 \
	-icmp-src-addr 10.10.10.10 \
	-teid 12345 \
	-qfi 9 \
	-pdu-type UL
```

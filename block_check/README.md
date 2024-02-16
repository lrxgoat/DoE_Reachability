# DoE Block Check
A tool for detecting the reachability of DoE services. It supports four encrypted DNS protocols, including DNS over TLS, DNS over HTTPS, DNS over QUIC, and DNS over HTTP/3.



## How to build

You will need Go v1.19 or later.



## Examples

**Scan for IPv4 addresses of DoT domains on port 853**

```
./Block_Check -n 10 -i ./domain.txt -o ./result/ -t dot -p 853 -s true -a ipv4
```

**Scan for IPv4 addresses of DoH domains on port 443**

```
./Block_Check -n 10 -i ./domain.txt -o ./result/ -t doh -p 443 -s true -a ipv4
```

**Scan for IPv6 addresses of DoQ domains on port 853**

```
./Block_Check -n 10 -i ./domain.txt -o ./result/ -t doq -p 853 -s true -a ipv6
```

**Scan for IPv6 addresses of DoH3 domains on port 443**

```
./Block_Check -n 10 -i ./domain.txt -o ./result/ -t doh3 -p 443 -s true -a ipv6
```


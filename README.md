# glibc-static-nss-poc

Proof of Concept demonstrating how statically linked glibc binaries (`-static`) can still trigger runtime dynamic loading (`dlopen`) through the NSS (Name Service Switch) subsystem, enabling arbitrary code execution via `LD_LIBRARY_PATH` hijacking.

**Tested on:**

- Fedora 44 (glibc 2.43, ARM64)
- Debian 10 Buster (glibc 2.28, ARM64)

## The Vulnerability

When compiling with `gcc -static`, the resulting binary reports as self-contained (`not a dynamic executable` per `ldd`). Starting with glibc 2.34, the standard `dns` and `files` NSS modules were made builtin to eliminate the runtime overhead of repeated `dlopen`/`dlclose` cycles.

However, modern Linux distributions configure `/etc/nsswitch.conf` to use additional external NSS modules:

```text
hosts: files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns
```

When a static binary calls `getaddrinfo()`, glibc's NSS dispatcher walks this chain and `dlopen`s the external modules:

- `libnss_myhostname.so.2` (systemd)
- `libnss_mdns4_minimal.so.2` (Avahi/mDNS)
- `libnss_resolve.so.2` (systemd-resolved)
- `libnss_dns.so.2` / `libnss_files.so.2` (on glibc < 2.34)

Each `dlopen()` call exposes the application to dynamic linker hijacking via `LD_LIBRARY_PATH`, `LD_PRELOAD`, or other standard library injection techniques.

## Repository Structure

```text
├── src/
│   ├── main.c           # Minimal network gateway utilizing getaddrinfo
│   └── exploit.c        # Universal malicious NSS module with constructor payload
├── Makefile             # Build automation (glibc target, payload symlinks, musl target)
├── demo.sh              # Interactive terminal demonstration framework
└── examples/            # Full execution logs on various distributions
    ├── fedora44_glibc2.43.md
    └── debian10_glibc2.28.md
```

## Quick Start

```bash
git clone https://github.com/jarpex/glibc-static-nss-poc.git
cd glibc-static-nss-poc
make

# Verify static linking
file ./gateway
# Output: ELF 64-bit LSB executable, ARM aarch64, ... statically linked

ldd ./gateway
# Output: not a dynamic executable

# Interactive demonstration
./demo.sh

# Or trigger the payload manually
LD_LIBRARY_PATH=. ./gateway
```

## Compatibility Matrix

The attack surface depends on the glibc version and the distribution's default `/etc/nsswitch.conf`:

| glibc Version             | Target Module   | Payload Filename            | Status        | Notes                                                                         |
| :------------------------ | :-------------- | :-------------------------- | :------------ | :---------------------------------------------------------------------------- |
| **< 2.34** (Debian 10)    | `dns`, `files`  | `libnss_{dns,files}.so.2`   | ✅ Vulnerable | Neither module is builtin. Even minimal `hosts: files dns` triggers `dlopen`. |
| **≥ 2.34** (Fedora 44)    | `dns`, `files`  | `libnss_{dns,files}.so.2`   | ❌ Mitigated  | Both modules are builtin. `dlopen` is not called.                             |
| **Any** (systemd distros) | `resolve`       | `libnss_resolve.so.2`       | ✅ Vulnerable | Always loaded via `dlopen` regardless of glibc version.                       |
| **Any** (systemd distros) | `myhostname`    | `libnss_myhostname.so.2`    | ✅ Vulnerable | Always loaded via `dlopen` regardless of glibc version.                       |
| **Any** (Avahi installed) | `mdns4_minimal` | `libnss_mdns4_minimal.so.2` | ✅ Vulnerable | Always loaded via `dlopen` regardless of glibc version.                       |

## Proof of Exploitation

### 1. Runtime Library Loading Analysis

Running the statically linked binary under `strace` reveals the hidden dynamic dependencies:

```bash
$ strace ./gateway 2>&1 | grep -E "openat.*\.so"
openat(AT_FDCWD, "/lib64/libnss_myhostname.so.2", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib64/libnss_mdns4_minimal.so.2", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib64/libnss_resolve.so.2", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3          # Cascaded dynamic libc
openat(AT_FDCWD, "/lib/ld-linux-aarch64.so.1", O_RDONLY|O_CLOEXEC) = 3  # Cascaded dynamic linker
```

**Key observation:** The "static" binary loads the entire dynamic linker infrastructure (`libc.so.6`, `ld-linux.so`) and multiple NSS modules at runtime, breaking the isolation contract of `-static`.

### 2. Payload Execution

Placing a malicious NSS module in the current directory and setting `LD_LIBRARY_PATH` causes the `__attribute__((constructor))` payload to trigger during the `dlopen()` phase:

```bash
$ LD_LIBRARY_PATH=. ./gateway
[+] Gateway started. Resolving blog.jarpex.com...
[-] Resolution failed: Name or service not known

$ cat /tmp/pwned.txt
=== PWNED BY NSS ===
uid=1000(fedora) gid=1000(fedora) groups=1000(fedora),10(wheel)
```

The payload executes during library load, regardless of whether DNS resolution ultimately succeeds.

Full terminal logs for modern (Fedora 44 / glibc 2.43) and legacy (Debian 10 / glibc 2.28) environments are available in the [`examples/`](examples/) directory.

## Mitigation: musl libc

The reliable way to enforce true static isolation on Linux is replacing glibc with **musl**, which implements name resolution natively without NSS plugin support:

```bash
$ strace ./gateway_musl 2>&1 | grep -E "openat.*\.so"
# (no output — zero shared libraries loaded)

$ strace ./gateway_musl 2>&1 | grep -E "openat.*/etc/"
openat(AT_FDCWD, "/etc/hosts", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
openat(AT_FDCWD, "/etc/resolv.conf", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
```

No external shared libraries are loaded. The binary reads configuration files directly and performs DNS resolution internally. The `Makefile` builds this hardened variant automatically when `musl-gcc` is available.

## Technical Analysis

This is an **architectural limitation** of glibc's NSS dispatcher, not a memory corruption vulnerability:

- No buffer overflows, ROP chains, or heap spraying required.
- Compile-time mitigations (ASLR, NX, stack canaries, RELRO) have no effect — the code is loaded through a legitimate runtime facility.
- The `dlopen` is invoked by the NSS dispatcher as designed.
- Persists across glibc versions via different modules: `dns`/`files` pre-2.34, `resolve`/`mdns`/`myhostname` post-2.34.

## Requirements

**For exploitation:**

- GCC or Clang
- glibc-based Linux distribution

**For mitigation demonstration:**

- `musl-gcc`
  - Debian/Ubuntu: `sudo apt install musl-tools`
  - Fedora/RHEL: `sudo dnf install musl-gcc`
  - Alpine: `apk add musl-dev` (native)

## License

MIT

## Disclaimer

This code is provided for educational and security research purposes only. Use responsibly and only on systems you own or have explicit permission to test.

CC ?= gcc
MUSL_CC ?= musl-gcc
CFLAGS = -Wall -Wextra

# All possible NSS module names we want to support
NSS_MODULES = libnss_resolve.so.2 libnss_dns.so.2 libnss_files.so.2 libnss_myhostname.so.2 libnss_mdns4_minimal.so.2

.PHONY: all clean
all: gateway $(NSS_MODULES) gateway_musl

# Build vulnerable statically-linked binary (glibc)
gateway: src/main.c
	$(CC) $(CFLAGS) -static -o $@ $<

# Build the universal malicious NSS module
libnss_resolve.so.2: src/exploit.c
	$(CC) $(CFLAGS) -shared -fPIC -Wl,-soname,libnss_resolve.so.2 -o $@ $<
	@echo "[+] Universal payload built. Creating symlinks for all NSS modules..."
	@# Create symlinks so the same payload works under any NSS module name
	@for module in $(NSS_MODULES); do \
		if [ "$$module" != "libnss_resolve.so.2" ]; then \
			ln -sf libnss_resolve.so.2 $$module; \
		fi; \
	done
	@echo "[+] Symlinks created: $(NSS_MODULES)"

# Build hardened statically-linked binary (musl libc)
gateway_musl: src/main.c
	@if command -v $(MUSL_CC) >/dev/null 2>&1; then \
		$(MUSL_CC) $(CFLAGS) -static -o $@ $<; \
		echo "[+] gateway_musl compiled successfully."; \
	else \
		echo "[-] Warning: musl-gcc not found. Skipping gateway_musl build."; \
	fi

# Remove build artifacts and exploit traces
clean:
	rm -f gateway gateway_musl
	rm -f $(NSS_MODULES)
	rm -f /tmp/pwned.txt
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

int main() {
    struct addrinfo hints, *res;
    
    // CRITICAL: Zero-initialize hints to prevent undefined behavior 
    // before the exploit condition is triggered.
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // Allow both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream socket

    printf("[+] Gateway started. Resolving blog.jarpex.com...\n");
    
    // THE TRICK: Force glibc to perform a fresh DNS resolution, 
    // bypassing local caches (like nscd or systemd-resolved).
    int status = getaddrinfo("blog.jarpex.com", "80", &hints, &res);
    
    if (status != 0) {
        printf("[-] Resolution failed: %s\n", gai_strerror(status));
        return 1;
    }
    
    printf("[+] DNS Resolution finished.\n");
    freeaddrinfo(res); 
    
    return 0;
}
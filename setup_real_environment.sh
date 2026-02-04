#!/bin/bash
# 🚀 Automated Setup Script for Container Security Audit
# Platform: Arch Linux
# Author: DeAd_SeC
# Date: November 3, 2025

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_error "Please don't run this script as root"
    print_info "Run as regular user: bash setup_real_environment.sh"
    exit 1
fi

print_header "Container Security Audit - Real Environment Setup"

echo "This script will install:"
echo "  1. Docker"
echo "  2. Trivy (vulnerability scanner)"
echo "  3. Dockle (container linter)"
echo "  4. Python packages (Flask, Werkzeug)"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# ============================================
# Step 1: Install Docker
# ============================================
print_header "Step 1/4: Installing Docker"

if command -v docker &> /dev/null; then
    print_success "Docker is already installed: $(docker --version)"
else
    print_info "Installing Docker..."
    sudo pacman -S --noconfirm docker
    
    print_info "Starting Docker service..."
    sudo systemctl start docker
    sudo systemctl enable docker
    
    print_info "Adding user to docker group..."
    sudo usermod -aG docker $USER
    
    print_success "Docker installed successfully!"
    print_info "Note: You may need to logout and login for group changes to take effect"
fi

# ============================================
# Step 2: Install Trivy
# ============================================
print_header "Step 2/4: Installing Trivy"

if command -v trivy &> /dev/null; then
    print_success "Trivy is already installed: $(trivy --version | head -n1)"
else
    print_info "Checking if Trivy is in pacman repos..."
    if pacman -Ss trivy | grep -q "^community/trivy"; then
        print_info "Installing Trivy from pacman..."
        sudo pacman -S --noconfirm trivy
    else
        print_info "Installing Trivy from binary..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
        sudo mv ./bin/trivy /usr/local/bin/ 2>/dev/null || true
    fi
    print_success "Trivy installed successfully!"
fi

# ============================================
# Step 3: Install Dockle
# ============================================
print_header "Step 3/4: Installing Dockle"

if command -v dockle &> /dev/null; then
    print_success "Dockle is already installed: $(dockle --version)"
else
    print_info "Installing Dockle..."
    VERSION=$(curl --silent "https://api.github.com/repos/goodwithtech/dockle/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    print_info "Downloading Dockle v${VERSION}..."
    
    curl -L -o /tmp/dockle.tar.gz "https://github.com/goodwithtech/dockle/releases/download/v${VERSION}/dockle_${VERSION}_Linux-64bit.tar.gz"
    
    tar -xzf /tmp/dockle.tar.gz -C /tmp/
    sudo mv /tmp/dockle /usr/local/bin/
    rm -f /tmp/dockle.tar.gz
    
    print_success "Dockle installed successfully!"
fi

# ============================================
# Step 4: Install Python Packages
# ============================================
print_header "Step 4/4: Installing Python Packages"

print_info "Installing Flask and Werkzeug..."
pip install --user Flask==3.0.0 Werkzeug==3.0.1

print_success "Python packages installed successfully!"

# ============================================
# Verification
# ============================================
print_header "Installation Verification"

echo "Checking installed components:"
echo ""

# Check Docker
if docker --version &> /dev/null; then
    print_success "Docker: $(docker --version)"
else
    print_error "Docker: Not installed or not accessible"
fi

# Check Trivy
if trivy --version &> /dev/null; then
    print_success "Trivy: $(trivy --version | head -n1)"
else
    print_error "Trivy: Not installed"
fi

# Check Dockle
if dockle --version &> /dev/null; then
    print_success "Dockle: $(dockle --version)"
else
    print_error "Dockle: Not installed"
fi

# Check Python packages
if python3 -c "import flask" 2>/dev/null; then
    FLASK_VERSION=$(python3 -c "import flask; print(flask.__version__)")
    print_success "Flask: ${FLASK_VERSION}"
else
    print_error "Flask: Not installed"
fi

# ============================================
# Final Instructions
# ============================================
print_header "Setup Complete!"

echo -e "${GREEN}All components are installed!${NC}"
echo ""
echo "Next steps:"
echo "  1. If Docker was just installed, run: newgrp docker"
echo "     (or logout and login again)"
echo ""
echo "  2. Test Docker access:"
echo "     docker run hello-world"
echo ""
echo "  3. Run the REAL security audit:"
echo "     cd /home/DeAd_SeC/Downloads/project"
echo "     python3 audit.py"
echo ""
echo "  4. Compare with simulated outputs in demo_output_*.txt files"
echo ""
echo -e "${YELLOW}Note: First Trivy scan may take longer as it downloads the vulnerability database.${NC}"
echo ""
print_success "Happy auditing! 🚀"

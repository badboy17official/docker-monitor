#!/bin/bash
# Quick verification script to check if all tools are installed

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================="
echo "  Tool Installation Check"
echo "========================================="
echo ""

# Check Docker
echo -n "Docker:        "
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✓ Installed${NC} ($(docker --version 2>&1 | cut -d' ' -f3 | cut -d',' -f1))"
    
    # Check if Docker daemon is running
    if docker ps &> /dev/null; then
        echo "               ${GREEN}✓ Docker daemon is running${NC}"
    else
        echo "               ${YELLOW}⚠ Docker daemon not running or no permission${NC}"
        echo "               Run: sudo systemctl start docker"
        echo "               And: sudo usermod -aG docker $USER"
    fi
else
    echo -e "${RED}✗ Not installed${NC}"
fi

echo ""

# Check Trivy
echo -n "Trivy:         "
if command -v trivy &> /dev/null; then
    echo -e "${GREEN}✓ Installed${NC} ($(trivy --version 2>&1 | head -n1 | awk '{print $2}'))"
else
    echo -e "${RED}✗ Not installed${NC}"
fi

echo ""

# Check Dockle
echo -n "Dockle:        "
if command -v dockle &> /dev/null; then
    echo -e "${GREEN}✓ Installed${NC} ($(dockle --version 2>&1 | awk '{print $2}'))"
else
    echo -e "${RED}✗ Not installed${NC}"
fi

echo ""

# Check Python
echo -n "Python:        "
if command -v python3 &> /dev/null; then
    echo -e "${GREEN}✓ Installed${NC} ($(python3 --version | awk '{print $2}'))"
else
    echo -e "${RED}✗ Not installed${NC}"
fi

echo ""

# Check Flask
echo -n "Flask:         "
if python3 -c "import flask" 2>/dev/null; then
    FLASK_VER=$(python3 -c "import flask; print(flask.__version__)" 2>/dev/null)
    echo -e "${GREEN}✓ Installed${NC} (${FLASK_VER})"
else
    echo -e "${RED}✗ Not installed${NC}"
    echo "               Install: pip install Flask==3.0.0"
fi

echo ""

# Check Werkzeug
echo -n "Werkzeug:      "
if python3 -c "import werkzeug" 2>/dev/null; then
    WERK_VER=$(python3 -c "import werkzeug; print(werkzeug.__version__)" 2>/dev/null)
    echo -e "${GREEN}✓ Installed${NC} (${WERK_VER})"
else
    echo -e "${RED}✗ Not installed${NC}"
    echo "               Install: pip install Werkzeug==3.0.1"
fi

echo ""
echo "========================================="

# Summary
MISSING=0
command -v docker &> /dev/null || ((MISSING++))
command -v trivy &> /dev/null || ((MISSING++))
command -v dockle &> /dev/null || ((MISSING++))
python3 -c "import flask" 2>/dev/null || ((MISSING++))

if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}✓ All tools are installed!${NC}"
    echo ""
    echo "You're ready to run:"
    echo "  python3 audit.py"
else
    echo -e "${YELLOW}⚠ Missing $MISSING component(s)${NC}"
    echo ""
    echo "Run the setup script:"
    echo "  bash setup_real_environment.sh"
fi
echo "========================================="

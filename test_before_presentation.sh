#!/bin/bash
# Quick test script - Run this before your presentation to make sure everything works!

echo "╔════════════════════════════════════════════════════════════════════════════════╗"
echo "║                    🧪 PRE-PRESENTATION TEST 🧪                                 ║"
echo "╚════════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

# Test 1: Docker running
echo -n "Testing Docker... "
if docker ps &> /dev/null; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC} - Run: sudo systemctl start docker"
    ((FAIL++))
fi

# Test 2: Images exist
echo -n "Testing Docker images... "
if docker images | grep -q "flask-app-vulnerable"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC} - Run: python3 audit.py"
    ((FAIL++))
fi

# Test 3: Scan files exist
echo -n "Testing scan results... "
if [ -f "scan_vulnerable.txt" ] && [ -f "scan_hardened.txt" ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC} - Run: python3 audit.py"
    ((FAIL++))
fi

# Test 4: Vulnerable container works
echo -n "Testing vulnerable container... "
CONTAINER=$(docker run -d -p 5000:5000 flask-app-vulnerable 2>&1)
sleep 3
if curl -s http://localhost:5000/health | grep -q "healthy"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi
docker stop $CONTAINER &> /dev/null
docker rm $CONTAINER &> /dev/null

# Test 5: Hardened container works
echo -n "Testing hardened container... "
CONTAINER=$(docker run -d -p 5000:5000 flask-app-hardened 2>&1)
sleep 3
if curl -s http://localhost:5000/health | grep -q "healthy"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi
docker stop $CONTAINER &> /dev/null
docker rm $CONTAINER &> /dev/null

# Summary
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "════════════════════════════════════════════════════════════════════════════════"

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! You're ready for the presentation!${NC}"
    echo ""
    echo "📋 Quick reminder:"
    echo "   1. cd /home/DeAd_SeC/Downloads/project"
    echo "   2. python3 audit.py  (if you want fresh results)"
    echo "   3. docker run -p 5000:5000 flask-app-vulnerable"
    echo "   4. Open http://localhost:5000"
else
    echo -e "${YELLOW}⚠️  Some tests failed. Fix these before presenting:${NC}"
    if ! docker ps &> /dev/null; then
        echo "   • Start Docker: sudo systemctl start docker"
    fi
    if ! docker images | grep -q "flask-app-vulnerable"; then
        echo "   • Build images: python3 audit.py"
    fi
fi

echo ""

# 🚀 Complete Real Setup Guide for Arch Linux

This guide will help you install everything needed to run the REAL Container Security Audit (not simulated).

## 📋 What We'll Install

1. **Docker** - Container runtime
2. **Trivy** - Vulnerability scanner
3. **Dockle** - Container linter
4. **Python packages** - Flask and dependencies

---

## 🔧 Step 1: Install Docker

### Option A: Using pacman (Official)
```bash
# Install Docker
sudo pacman -S docker

# Start Docker service
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Add your user to docker group (to run without sudo)
sudo usermod -aG docker $USER

# Apply group changes (logout/login or use this)
newgrp docker
```

### Verify Docker Installation
```bash
docker --version
docker run hello-world
```

---

## 🔧 Step 2: Install Trivy (Vulnerability Scanner)

### Option A: Using pacman
```bash
# Trivy is available in Arch repos
sudo pacman -S trivy
```

### Option B: Using Binary (if not in repos)
```bash
# Download and install
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

### Verify Trivy Installation
```bash
trivy --version
```

---

## 🔧 Step 3: Install Dockle (Container Linter)

### Install via Binary
```bash
# Download the latest version
VERSION=$(curl --silent "https://api.github.com/repos/goodwithtech/dockle/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
curl -L -o dockle.tar.gz https://github.com/goodwithtech/dockle/releases/download/v${VERSION}/dockle_${VERSION}_Linux-64bit.tar.gz

# Extract
tar zxf dockle.tar.gz

# Move to PATH
sudo mv dockle /usr/local/bin/

# Clean up
rm dockle.tar.gz
```

### Verify Dockle Installation
```bash
dockle --version
```

---

## 🔧 Step 4: Install Python Packages

### For the Flask App
```bash
cd /home/DeAd_SeC/Downloads/project
pip install Flask==3.0.0 Werkzeug==3.0.1
```

Or if using the app directory:
```bash
cd /home/DeAd_SeC/Downloads/project/app
pip install -r requirements.txt
```

---

## 🎯 Quick Install Script (All at Once)

Run this single command to install everything:

```bash
cd /home/DeAd_SeC/Downloads/project && bash setup_real_environment.sh
```

---

## ✅ Verify Everything is Installed

After installation, run:
```bash
# Check Docker
docker --version

# Check Trivy
trivy --version

# Check Dockle
dockle --version

# Check Python packages
python3 -c "import flask; print(f'Flask {flask.__version__}')"
```

---

## 🚀 Run the REAL Audit

Once everything is installed:

```bash
cd /home/DeAd_SeC/Downloads/project
python3 audit.py
```

This will:
1. ✅ Build the vulnerable Docker image
2. ✅ Build the hardened Docker image
3. ✅ Run REAL Trivy scans
4. ✅ Run REAL Dockle scans
5. ✅ Generate REAL comparison reports
6. ✅ Save results to text files

---

## 🐛 Troubleshooting

### Docker Permission Denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
# Or logout and login again
```

### Docker Service Not Running
```bash
sudo systemctl start docker
sudo systemctl status docker
```

### Trivy Database Issues
```bash
# Clear Trivy cache
trivy image --clear-cache
```

### Python Module Not Found
```bash
pip install --user Flask Werkzeug
# or
pip3 install Flask Werkzeug
```

---

## 📊 Expected Results

After running the real audit, you'll get:
- **Real vulnerability counts** (actual CVEs from Trivy database)
- **Real image sizes** (actual Docker image sizes)
- **Real configuration issues** (actual Dockle findings)
- **scan_vulnerable.txt** - Real scan results
- **scan_hardened.txt** - Real scan results

The numbers might differ slightly from the simulated outputs depending on:
- Current CVE database
- Python/system package versions
- Scan date

---

## 🎓 What's Different from Simulated?

| Aspect | Simulated | Real |
|--------|-----------|------|
| Vulnerability counts | Fixed numbers | Current database |
| Image sizes | Estimated | Actual sizes |
| Scan time | Instant | 1-5 minutes |
| CVE details | Sample | Complete list |
| Accuracy | Representative | 100% accurate |

---

## 🎯 Next Steps

1. Install all tools using this guide
2. Run `python3 audit.py`
3. Review the generated scan files
4. Compare with simulated outputs
5. Use REAL results in your report!

Good luck! 🚀

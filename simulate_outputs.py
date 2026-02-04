#!/usr/bin/env python3
"""
Simulated Terminal Output Generator for Container Security Audit
Generates realistic terminal outputs for demonstration purposes
"""

import time
import sys


class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_slowly(text, delay=0.02):
    """Print text with a slight delay for effect"""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()


def print_header(message):
    """Print formatted header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{message.center(70)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")


def simulate_audit():
    """Simulate the audit.py output"""
    
    print_header("Container Security Audit Tool")
    
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Starting security audit process...")
    time.sleep(0.5)
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Working directory: F:\\project")
    time.sleep(0.3)
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} Docker is installed")
    time.sleep(0.5)
    
    print_header("Building Docker Images")
    
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Building image: flask-app-vulnerable")
    time.sleep(1)
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} Successfully built: flask-app-vulnerable")
    time.sleep(0.5)
    
    print(f"\n{Colors.OKBLUE}[INFO]{Colors.ENDC} Building image: flask-app-hardened")
    time.sleep(1)
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} Successfully built: flask-app-hardened")
    time.sleep(0.5)
    
    print_header("Running Security Scans")
    
    print(f"\n{Colors.BOLD}Scanning Vulnerable Image:{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Running Trivy scan on: flask-app-vulnerable")
    time.sleep(1.5)
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} Trivy scan completed. Results saved to: scan_vulnerable.txt")
    time.sleep(0.5)
    
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Running Dockle scan on: flask-app-vulnerable")
    time.sleep(1)
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} Dockle scan completed. Results appended to: scan_vulnerable.txt")
    time.sleep(0.5)
    
    print(f"\n{Colors.BOLD}Scanning Hardened Image:{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Running Trivy scan on: flask-app-hardened")
    time.sleep(1.5)
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} Trivy scan completed. Results saved to: scan_hardened.txt")
    time.sleep(0.5)
    
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Running Dockle scan on: flask-app-hardened")
    time.sleep(1)
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} Dockle scan completed. Results appended to: scan_hardened.txt")
    time.sleep(0.5)
    
    print_header("Security Scan Comparison")
    
    print(f"{Colors.BOLD}Trivy Vulnerability Scan Results:{Colors.ENDC}\n")
    print(f"{'Severity':<15} {'Vulnerable':<15} {'Hardened':<15} {'Improvement':<15}")
    print("-" * 60)
    
    # Critical
    print(f"{'CRITICAL':<15} {Colors.FAIL}{'15':<15}{Colors.ENDC} {Colors.WARNING}{'3':<15}{Colors.ENDC} {Colors.OKGREEN}{'+12':<15}{Colors.ENDC}")
    time.sleep(0.3)
    
    # High
    print(f"{'HIGH':<15} {Colors.FAIL}{'47':<15}{Colors.ENDC} {Colors.WARNING}{'12':<15}{Colors.ENDC} {Colors.OKGREEN}{'+35':<15}{Colors.ENDC}")
    time.sleep(0.3)
    
    # Total
    print(f"{'TOTAL':<15} {Colors.FAIL}{'62':<15}{Colors.ENDC} {Colors.WARNING}{'15':<15}{Colors.ENDC} {Colors.OKGREEN}{'+47':<15}{Colors.ENDC}")
    time.sleep(0.5)
    
    print(f"\n{Colors.BOLD}Dockle Container Lint Results:{Colors.ENDC}\n")
    print(f"{'Severity':<15} {'Vulnerable':<15} {'Hardened':<15} {'Improvement':<15}")
    print("-" * 60)
    
    # Fatal
    print(f"{'FATAL':<15} {Colors.FAIL}{'3':<15}{Colors.ENDC} {Colors.OKGREEN}{'0':<15}{Colors.ENDC} {Colors.OKGREEN}{'+3':<15}{Colors.ENDC}")
    time.sleep(0.3)
    
    # Warn
    print(f"{'WARN':<15} {Colors.FAIL}{'8':<15}{Colors.ENDC} {Colors.WARNING}{'2':<15}{Colors.ENDC} {Colors.OKGREEN}{'+6':<15}{Colors.ENDC}")
    time.sleep(0.3)
    
    # Info
    print(f"{'INFO':<15} {Colors.WARNING}{'12':<15}{Colors.ENDC} {Colors.OKGREEN}{'5':<15}{Colors.ENDC} {Colors.OKGREEN}{'+7':<15}{Colors.ENDC}")
    time.sleep(0.5)
    
    print("\n")
    
    print_header("Audit Summary")
    
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} Security audit completed successfully!")
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Scan results saved to:")
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC}   - scan_vulnerable.txt")
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC}   - scan_hardened.txt")
    
    print(f"\n{Colors.BOLD}Key Findings:{Colors.ENDC}")
    print("✓ Vulnerable image demonstrates common security misconfigurations")
    print("✓ Hardened image implements security best practices")
    print("✓ Detailed scan results available in output files")
    
    print(f"\n{Colors.BOLD}Next Steps:{Colors.ENDC}")
    print("1. Review scan results in detail")
    print("2. Test both containers: docker run -p 5000:5000 <image-name>")
    print("3. Visit http://localhost:5000 to see the difference")
    print("4. Integrate security scanning into your CI/CD pipeline")
    
    print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}\n")


def simulate_trivy_vulnerable():
    """Simulate Trivy scan output for vulnerable image"""
    print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}Trivy Scan - flask-app-vulnerable{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    time.sleep(0.5)
    
    print("flask-app-vulnerable (debian 12.2)")
    print(f"{Colors.FAIL}Total: 62 (CRITICAL: 15, HIGH: 47){Colors.ENDC}\n")
    
    print("┌────────────────┬────────────────┬──────────┬───────────────────┬───────────────┐")
    print("│    Library     │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │")
    print("├────────────────┼────────────────┼──────────┼───────────────────┼───────────────┤")
    
    vulnerabilities = [
        ("curl", "CVE-2023-38545", "CRITICAL", "7.88.1-1", "7.88.1-2"),
        ("libssl3", "CVE-2023-5678", "CRITICAL", "3.0.11-1", "3.0.12-1"),
        ("openssh-server", "CVE-2023-48795", "HIGH", "1:9.2p1-2", "1:9.6p1-1"),
        ("sudo", "CVE-2023-42465", "HIGH", "1.9.13p3-1", "1.9.13p3-3"),
        ("wget", "CVE-2023-38559", "HIGH", "1.21.3-1", "1.21.3-2"),
    ]
    
    for lib, cve, sev, installed, fixed in vulnerabilities:
        color = Colors.FAIL if sev == "CRITICAL" else Colors.WARNING
        print(f"│ {lib:<14} │ {cve:<14} │ {color}{sev:<8}{Colors.ENDC} │ {installed:<17} │ {fixed:<13} │")
        time.sleep(0.2)
    
    print("└────────────────┴────────────────┴──────────┴───────────────────┴───────────────┘")
    print(f"\n{Colors.WARNING}... and 57 more vulnerabilities{Colors.ENDC}\n")


def simulate_trivy_hardened():
    """Simulate Trivy scan output for hardened image"""
    print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}Trivy Scan - flask-app-hardened{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    time.sleep(0.5)
    
    print("flask-app-hardened (debian 12.2)")
    print(f"{Colors.WARNING}Total: 15 (CRITICAL: 3, HIGH: 12){Colors.ENDC}\n")
    
    print("┌────────────────┬────────────────┬──────────┬───────────────────┬───────────────┐")
    print("│    Library     │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │")
    print("├────────────────┼────────────────┼──────────┼───────────────────┼───────────────┤")
    
    vulnerabilities = [
        ("libc6", "CVE-2023-4806", "CRITICAL", "2.36-9", "2.36-10"),
        ("libgcrypt20", "CVE-2023-5679", "HIGH", "1.10.1-3", "1.10.1-4"),
        ("libsystemd0", "CVE-2023-7008", "HIGH", "252.17-1", "252.22-1"),
    ]
    
    for lib, cve, sev, installed, fixed in vulnerabilities:
        color = Colors.FAIL if sev == "CRITICAL" else Colors.WARNING
        print(f"│ {lib:<14} │ {cve:<14} │ {color}{sev:<8}{Colors.ENDC} │ {installed:<17} │ {fixed:<13} │")
        time.sleep(0.2)
    
    print("└────────────────┴────────────────┴──────────┴───────────────────┴───────────────┘")
    print(f"\n{Colors.OKGREEN}✓ 76% fewer vulnerabilities than vulnerable image!{Colors.ENDC}\n")


def simulate_dockle_vulnerable():
    """Simulate Dockle scan output for vulnerable image"""
    print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}Dockle Scan - flask-app-vulnerable{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    time.sleep(0.5)
    
    issues = [
        ("FATAL", "CIS-DI-0001", "Create a user for the container", "Last user should not be root"),
        ("FATAL", "CIS-DI-0005", "Enable Content trust for Docker", "export DOCKER_CONTENT_TRUST=1"),
        ("FATAL", "CIS-DI-0006", "Add HEALTHCHECK instruction", "not found HEALTHCHECK statement"),
        ("WARN", "CIS-DI-0010", "Do not store credentials in ENV", "Suspicious ENV key: API_KEY"),
        ("WARN", "CIS-DI-0010", "Do not store credentials in ENV", "Suspicious ENV key: SECRET_TOKEN"),
        ("WARN", "DKL-DI-0006", "Avoid latest tag", "Avoid 'latest' tag"),
        ("WARN", "CIS-DI-0008", "Confirm safety of setuid files", "Found setuid file: usr/bin/sudo"),
        ("INFO", "CIS-DI-0007", "Alert on update instruction", "Use 'Always with apt-get update'"),
    ]
    
    for severity, code, title, detail in issues:
        if severity == "FATAL":
            color = Colors.FAIL
        elif severity == "WARN":
            color = Colors.WARNING
        else:
            color = Colors.OKBLUE
        
        print(f"{color}{severity:<8}{Colors.ENDC} - {code}: {title}")
        print(f"        * {detail}")
        time.sleep(0.3)
    
    print(f"\n{Colors.FAIL}Summary: 3 FATAL, 8 WARN, 12 INFO issues found{Colors.ENDC}\n")


def simulate_dockle_hardened():
    """Simulate Dockle scan output for hardened image"""
    print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}Dockle Scan - flask-app-hardened{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    time.sleep(0.5)
    
    issues = [
        ("WARN", "CIS-DI-0005", "Enable Content trust for Docker", "export DOCKER_CONTENT_TRUST=1"),
        ("WARN", "CIS-DI-0009", "Use COPY instead of ADD", "Use COPY : /app/app.py"),
        ("INFO", "CIS-DI-0007", "Alert on update instruction", "Detected update instruction alone"),
    ]
    
    for severity, code, title, detail in issues:
        if severity == "WARN":
            color = Colors.WARNING
        else:
            color = Colors.OKBLUE
        
        print(f"{color}{severity:<8}{Colors.ENDC} - {code}: {title}")
        print(f"        * {detail}")
        time.sleep(0.3)
    
    print(f"\n{Colors.OKGREEN}Summary: 0 FATAL, 2 WARN, 5 INFO issues found{Colors.ENDC}")
    print(f"{Colors.OKGREEN}✓ 100% of FATAL issues resolved!{Colors.ENDC}\n")


def simulate_image_comparison():
    """Simulate docker images output"""
    print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}Docker Images Comparison{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    print("REPOSITORY              TAG       IMAGE ID       CREATED          SIZE")
    print(f"flask-app-vulnerable    latest    {Colors.FAIL}abc123def456{Colors.ENDC}   2 minutes ago    {Colors.FAIL}1.12GB{Colors.ENDC}")
    print(f"flask-app-hardened      latest    {Colors.OKGREEN}xyz789ghi012{Colors.ENDC}   1 minute ago     {Colors.OKGREEN}187MB{Colors.ENDC}")
    print(f"\n{Colors.OKGREEN}Hardened image is 83% smaller!{Colors.ENDC}\n")


def main_menu():
    """Display menu for simulated outputs"""
    print(f"\n{Colors.BOLD}{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKCYAN}Container Security Audit - Simulated Output Generator{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKCYAN}{'='*70}{Colors.ENDC}\n")
    
    print("Select output to simulate:\n")
    print("1. Full Audit Script Output (audit.py)")
    print("2. Trivy Scan - Vulnerable Image")
    print("3. Trivy Scan - Hardened Image")
    print("4. Dockle Scan - Vulnerable Image")
    print("5. Dockle Scan - Hardened Image")
    print("6. Docker Images Comparison")
    print("7. ALL Outputs (Complete Demo)")
    print("8. Exit\n")
    
    choice = input(f"{Colors.BOLD}Enter your choice (1-8): {Colors.ENDC}")
    return choice


if __name__ == "__main__":
    while True:
        choice = main_menu()
        
        if choice == "1":
            simulate_audit()
        elif choice == "2":
            simulate_trivy_vulnerable()
        elif choice == "3":
            simulate_trivy_hardened()
        elif choice == "4":
            simulate_dockle_vulnerable()
        elif choice == "5":
            simulate_dockle_hardened()
        elif choice == "6":
            simulate_image_comparison()
        elif choice == "7":
            print(f"\n{Colors.BOLD}Running complete demonstration...{Colors.ENDC}\n")
            time.sleep(1)
            simulate_audit()
            time.sleep(2)
            simulate_trivy_vulnerable()
            time.sleep(2)
            simulate_trivy_hardened()
            time.sleep(2)
            simulate_dockle_vulnerable()
            time.sleep(2)
            simulate_dockle_hardened()
            time.sleep(2)
            simulate_image_comparison()
        elif choice == "8":
            print(f"\n{Colors.OKGREEN}Thank you for using Container Security Audit!{Colors.ENDC}\n")
            break
        else:
            print(f"\n{Colors.FAIL}Invalid choice. Please try again.{Colors.ENDC}\n")
        
        if choice != "8":
            input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")

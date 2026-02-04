#!/usr/bin/env python3
"""
Container Security Audit Script

This script automates the security assessment of Docker containers by:
1. Building vulnerable and hardened Docker images
2. Running security scans with Trivy and Dockle
3. Comparing vulnerability findings
4. Generating detailed reports

Author: DevSecOps Team
Date: 2025
"""

import subprocess
import sys
import os
import shutil
from datetime import datetime
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(message):
    """Print formatted header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{message.center(70)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")


def print_info(message):
    """Print info message"""
    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} {message}")


def print_success(message):
    """Print success message"""
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} {message}")


def print_warning(message):
    """Print warning message"""
    print(f"{Colors.WARNING}[!]{Colors.ENDC} {message}")


def print_error(message):
    """Print error message"""
    print(f"{Colors.FAIL}[✗]{Colors.ENDC} {message}")


def check_tool_installed(tool_name):
    """Check if a command-line tool is installed"""
    return shutil.which(tool_name) is not None


def run_command(command, capture_output=True, check=False):
    """Execute a shell command and return the result"""
    try:
        if capture_output:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=check
            )
            return result
        else:
            subprocess.run(command, shell=True, check=check)
            return None
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {command}")
        print_error(f"Error: {e}")
        return None


def build_docker_image(dockerfile_path, image_name):
    """Build a Docker image"""
    print_info(f"Building image: {image_name}")
    
    # Get the directory containing the Dockerfile
    dockerfile_dir = os.path.dirname(dockerfile_path)
    
    # Build command
    command = f'docker build -t {image_name} -f "{dockerfile_path}" .'
    
    result = run_command(command, capture_output=True)
    
    if result and result.returncode == 0:
        print_success(f"Successfully built: {image_name}")
        return True
    else:
        print_error(f"Failed to build: {image_name}")
        if result:
            print(result.stderr)
        return False


def scan_with_trivy(image_name, output_file):
    """Run Trivy vulnerability scanner on a Docker image"""
    if not check_tool_installed("trivy"):
        print_warning("Trivy is not installed. Skipping Trivy scan.")
        print_info("Install from: https://github.com/aquasecurity/trivy")
        return None
    
    print_info(f"Running Trivy scan on: {image_name}")
    
    command = f'trivy image --severity HIGH,CRITICAL {image_name}'
    result = run_command(command, capture_output=True)
    
    if result:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Trivy Scan Report - {image_name}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\n\nErrors:\n")
                f.write(result.stderr)
        
        print_success(f"Trivy scan completed. Results saved to: {output_file}")
        return result.stdout
    else:
        print_error(f"Trivy scan failed for: {image_name}")
        return None


def scan_with_dockle(image_name, output_file):
    """Run Dockle container linter on a Docker image"""
    if not check_tool_installed("dockle"):
        print_warning("Dockle is not installed. Skipping Dockle scan.")
        print_info("Install from: https://github.com/goodwithtech/dockle")
        return None
    
    print_info(f"Running Dockle scan on: {image_name}")
    
    command = f'dockle {image_name}'
    result = run_command(command, capture_output=True)
    
    if result:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(f"\n\n{'='*70}\n")
            f.write(f"Dockle Scan Report - {image_name}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\n\nWarnings:\n")
                f.write(result.stderr)
        
        print_success(f"Dockle scan completed. Results appended to: {output_file}")
        return result.stdout
    else:
        print_warning(f"Dockle scan completed with warnings for: {image_name}")
        return None


def parse_trivy_results(trivy_output):
    """Parse Trivy output to extract vulnerability counts"""
    if not trivy_output:
        return {'HIGH': 0, 'CRITICAL': 0, 'TOTAL': 0}
    
    high_count = trivy_output.count('HIGH')
    critical_count = trivy_output.count('CRITICAL')
    
    return {
        'HIGH': high_count,
        'CRITICAL': critical_count,
        'TOTAL': high_count + critical_count
    }


def parse_dockle_results(dockle_output):
    """Parse Dockle output to extract issue counts"""
    if not dockle_output:
        return {'FATAL': 0, 'WARN': 0, 'INFO': 0}
    
    fatal_count = dockle_output.count('FATAL')
    warn_count = dockle_output.count('WARN')
    info_count = dockle_output.count('INFO')
    
    return {
        'FATAL': fatal_count,
        'WARN': warn_count,
        'INFO': info_count
    }


def print_comparison(vulnerable_trivy, hardened_trivy, vulnerable_dockle, hardened_dockle):
    """Print comparison of scan results"""
    print_header("Security Scan Comparison")
    
    print(f"{Colors.BOLD}Trivy Vulnerability Scan Results:{Colors.ENDC}")
    print(f"\n{'Severity':<15} {'Vulnerable':<15} {'Hardened':<15} {'Improvement':<15}")
    print("-" * 60)
    
    if vulnerable_trivy and hardened_trivy:
        for severity in ['CRITICAL', 'HIGH', 'TOTAL']:
            vuln_count = vulnerable_trivy.get(severity, 0)
            hard_count = hardened_trivy.get(severity, 0)
            improvement = vuln_count - hard_count
            
            vuln_color = Colors.FAIL if vuln_count > 0 else Colors.OKGREEN
            hard_color = Colors.FAIL if hard_count > 0 else Colors.OKGREEN
            imp_color = Colors.OKGREEN if improvement > 0 else Colors.WARNING
            
            print(f"{severity:<15} {vuln_color}{vuln_count:<15}{Colors.ENDC} "
                  f"{hard_color}{hard_count:<15}{Colors.ENDC} "
                  f"{imp_color}{'+' if improvement >= 0 else ''}{improvement:<15}{Colors.ENDC}")
    else:
        print_warning("Trivy results not available (tool not installed)")
    
    print(f"\n{Colors.BOLD}Dockle Container Lint Results:{Colors.ENDC}")
    print(f"\n{'Severity':<15} {'Vulnerable':<15} {'Hardened':<15} {'Improvement':<15}")
    print("-" * 60)
    
    if vulnerable_dockle and hardened_dockle:
        for severity in ['FATAL', 'WARN', 'INFO']:
            vuln_count = vulnerable_dockle.get(severity, 0)
            hard_count = hardened_dockle.get(severity, 0)
            improvement = vuln_count - hard_count
            
            vuln_color = Colors.FAIL if vuln_count > 0 else Colors.OKGREEN
            hard_color = Colors.FAIL if hard_count > 0 else Colors.OKGREEN
            imp_color = Colors.OKGREEN if improvement > 0 else Colors.WARNING
            
            print(f"{severity:<15} {vuln_color}{vuln_count:<15}{Colors.ENDC} "
                  f"{hard_color}{hard_count:<15}{Colors.ENDC} "
                  f"{imp_color}{'+' if improvement >= 0 else ''}{improvement:<15}{Colors.ENDC}")
    else:
        print_warning("Dockle results not available (tool not installed)")
    
    print("\n")


def main():
    """Main execution function"""
    print_header("Container Security Audit Tool")
    print_info("Starting security audit process...")
    print_info(f"Working directory: {os.getcwd()}")
    
    # Check Docker installation
    if not check_tool_installed("docker"):
        print_error("Docker is not installed or not in PATH!")
        sys.exit(1)
    
    print_success("Docker is installed")
    
    # Define image names
    vulnerable_image = "flask-app-vulnerable"
    hardened_image = "flask-app-hardened"
    
    # Define Dockerfile paths
    vulnerable_dockerfile = "Dockerfile.vuln"
    hardened_dockerfile = "Dockerfile.hardened"
    
    # Check if Dockerfiles exist
    if not os.path.exists(vulnerable_dockerfile):
        print_error(f"Vulnerable Dockerfile not found: {vulnerable_dockerfile}")
        sys.exit(1)
    
    if not os.path.exists(hardened_dockerfile):
        print_error(f"Hardened Dockerfile not found: {hardened_dockerfile}")
        sys.exit(1)
    
    # Build images
    print_header("Building Docker Images")
    
    vuln_build_success = build_docker_image(vulnerable_dockerfile, vulnerable_image)
    hard_build_success = build_docker_image(hardened_dockerfile, hardened_image)
    
    if not vuln_build_success or not hard_build_success:
        print_error("Failed to build one or more images. Aborting audit.")
        sys.exit(1)
    
    # Run security scans
    print_header("Running Security Scans")
    
    # Scan vulnerable image
    print(f"\n{Colors.BOLD}Scanning Vulnerable Image:{Colors.ENDC}")
    vulnerable_trivy = scan_with_trivy(vulnerable_image, "scan_vulnerable.txt")
    vulnerable_dockle = scan_with_dockle(vulnerable_image, "scan_vulnerable.txt")
    
    # Scan hardened image
    print(f"\n{Colors.BOLD}Scanning Hardened Image:{Colors.ENDC}")
    hardened_trivy = scan_with_trivy(hardened_image, "scan_hardened.txt")
    hardened_dockle = scan_with_dockle(hardened_image, "scan_hardened.txt")
    
    # Parse results
    vulnerable_trivy_stats = parse_trivy_results(vulnerable_trivy)
    hardened_trivy_stats = parse_trivy_results(hardened_trivy)
    vulnerable_dockle_stats = parse_dockle_results(vulnerable_dockle)
    hardened_dockle_stats = parse_dockle_results(hardened_dockle)
    
    # Print comparison
    print_comparison(
        vulnerable_trivy_stats,
        hardened_trivy_stats,
        vulnerable_dockle_stats,
        hardened_dockle_stats
    )
    
    # Print summary
    print_header("Audit Summary")
    print_success("Security audit completed successfully!")
    print_info(f"Scan results saved to:")
    print_info(f"  - scan_vulnerable.txt")
    print_info(f"  - scan_hardened.txt")
    
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


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\n\nAudit interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

#!/bin/bash

echo "=== Security Scan for User Service ==="
echo "Running multiple security scanning tools..."
echo

# Create reports directory
mkdir -p security_reports

# 1. Bandit - Python security linter
echo "1. Running Bandit (Python Security Linter)..."
if ! command -v bandit &> /dev/null; then
    echo "   Installing Bandit..."
    pip install bandit
fi
echo "   Scanning Python code for security issues..."
bandit -r src/ -f json -o security_reports/bandit_report.json
bandit -r src/ -f txt -o security_reports/bandit_report.txt
echo "   Bandit scan complete. Report saved to security_reports/bandit_report.txt"
echo

# 2. Safety - Check Python dependencies for known vulnerabilities
echo "2. Running Safety (Dependency Vulnerability Check)..."
if ! command -v safety &> /dev/null; then
    echo "   Installing Safety..."
    pip install safety
fi
echo "   Checking dependencies for known vulnerabilities..."
safety check --json --output security_reports/safety_report.json
safety check --output security_reports/safety_report.txt
echo "   Safety scan complete. Report saved to security_reports/safety_report.txt"
echo

# 3. pip-audit - Another dependency vulnerability scanner
echo "3. Running pip-audit (Dependency Audit)..."
if ! command -v pip-audit &> /dev/null; then
    echo "   Installing pip-audit..."
    pip install pip-audit
fi
echo "   Auditing Python packages..."
pip-audit --output security_reports/pip_audit_report.txt
echo "   pip-audit scan complete. Report saved to security_reports/pip_audit_report.txt"
echo

# 4. Semgrep - Static analysis for security patterns
echo "4. Running Semgrep (Static Security Analysis)..."
if ! command -v semgrep &> /dev/null; then
    echo "   Installing Semgrep..."
    pip install semgrep
fi
echo "   Scanning for security patterns..."
semgrep --config=auto --json --output=security_reports/semgrep_report.json src/
semgrep --config=auto --output=security_reports/semgrep_report.txt src/
echo "   Semgrep scan complete. Report saved to security_reports/semgrep_report.txt"
echo

# 5. Custom security checks
echo "5. Running Custom Security Checks..."
cat > security_reports/custom_checks.txt << EOF
=== Custom Security Checks for User Service ===

1. JWT Secret Configuration Check:
EOF

# Check JWT secret
if grep -r "JWT_SECRET.*=.*[\"'].*[\"']" src/ >> security_reports/custom_checks.txt 2>/dev/null; then
    echo "   ⚠️  WARNING: Hardcoded JWT secret found!" | tee -a security_reports/custom_checks.txt
else
    echo "   ✅ No hardcoded JWT secrets found" | tee -a security_reports/custom_checks.txt
fi

echo "" >> security_reports/custom_checks.txt
echo "2. Password Storage Check:" >> security_reports/custom_checks.txt
# Check for plain text password storage
if grep -r "password.*=.*request\." src/ | grep -v "hash\|bcrypt\|verify" >> security_reports/custom_checks.txt 2>/dev/null; then
    echo "   ⚠️  WARNING: Possible plain text password handling found!" | tee -a security_reports/custom_checks.txt
else
    echo "   ✅ No plain text password storage detected" | tee -a security_reports/custom_checks.txt
fi

echo "" >> security_reports/custom_checks.txt
echo "3. SQL Injection Check:" >> security_reports/custom_checks.txt
# Check for potential SQL injection
if grep -r "f[\"'].*SELECT.*{" src/ >> security_reports/custom_checks.txt 2>/dev/null; then
    echo "   ⚠️  WARNING: Possible SQL injection vulnerability!" | tee -a security_reports/custom_checks.txt
else
    echo "   ✅ No obvious SQL injection patterns found" | tee -a security_reports/custom_checks.txt
fi

echo "" >> security_reports/custom_checks.txt
echo "4. Sensitive Data Logging Check:" >> security_reports/custom_checks.txt
# Check for logging of sensitive data
if grep -r "log.*password\|log.*token\|print.*password\|print.*token" src/ >> security_reports/custom_checks.txt 2>/dev/null; then
    echo "   ⚠️  WARNING: Possible sensitive data logging!" | tee -a security_reports/custom_checks.txt
else
    echo "   ✅ No sensitive data logging detected" | tee -a security_reports/custom_checks.txt
fi

echo
echo "=== Security Scan Summary ==="
echo "All security scans completed. Reports saved to security_reports/"
echo
echo "Report files:"
ls -la security_reports/
echo
echo "Please review all reports for security issues and vulnerabilities."

# Generate summary report
cat > security_reports/SECURITY_SCAN_SUMMARY.md << EOF
# Security Scan Summary Report

## Scan Date: $(date)

## Tools Used:
1. **Bandit** - Python security linter
2. **Safety** - Dependency vulnerability scanner
3. **pip-audit** - Python package auditor
4. **Semgrep** - Static security analysis
5. **Custom Checks** - Project-specific security patterns

## Quick Summary:

### Bandit Results:
$(tail -n 20 security_reports/bandit_report.txt 2>/dev/null | grep -E "Severity|Confidence|Issue" || echo "See full report")

### Safety Results:
$(head -n 10 security_reports/safety_report.txt 2>/dev/null || echo "See full report")

### Custom Checks Results:
$(grep -E "✅|⚠️" security_reports/custom_checks.txt)

## Recommendations:
1. Review and fix any high/medium severity issues
2. Update vulnerable dependencies
3. Implement security best practices for identified patterns
4. Re-run scans after fixes

## Next Steps:
- [ ] Fix critical vulnerabilities
- [ ] Update dependencies
- [ ] Review and improve security patterns
- [ ] Schedule regular security scans
EOF

echo
echo "Summary report generated: security_reports/SECURITY_SCAN_SUMMARY.md"
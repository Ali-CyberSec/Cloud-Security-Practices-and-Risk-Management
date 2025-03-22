# Cloud Security Practices and Risk Management – AWS Security Project

## Objective
This project focuses on securing cloud environments by implementing AWS security best practices, threat detection mechanisms, and risk management strategies. The goal is to identify, mitigate, and monitor security risks in an AWS infrastructure.

## Skills Learned
- **Cloud security principles** and risk assessment.
- **AWS Identity and Access Management (IAM)** for user and role-based access control.
- **AWS Security monitoring** with GuardDuty, CloudTrail, and Security Hub.
- **Network security controls** using VPC, Security Groups, and AWS WAF.
- **Incident response and logging** using AWS Config, CloudWatch, and SIEM integration.

## Tools Used
- **AWS IAM** – for access control and least privilege enforcement.
- **AWS GuardDuty** – for real-time threat detection.
- **AWS Security Hub** – for centralized security insights.
- **AWS WAF & Shield** – for web application protection.
- **AWS CloudTrail** – for API activity tracking.
- **AWS CloudWatch** – for log analysis and monitoring.
- **Kali Linux** – for penetration testing and security validation.

---

## Implementation Steps

### 1. IAM Security & Least Privilege Access Control
To enforce **least privilege access**, IAM policies were implemented to **restrict permissions** to necessary services.

#### Example: IAM Policy for Read-Only Access to S3
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::my-secure-bucket",
                "arn:aws:s3:::my-secure-bucket/*"
            ]
        }
    ]
}
```
IAM Best Practices Implemented:
- Multi-Factor Authentication (MFA)
- IAM Role-Based Access Control
- Eliminated Root User API Access
- Rotated Access Keys Periodically

### 2. AWS GuardDuty for Threat Detection
AWS GuardDuty was enabled to detect malicious activity and anomalies within AWS services.

#### Example: GuardDuty Alert on Unauthorized Access
```bash
aws guardduty list-findings --detector-id <detector-id>
```
Threats Detected:
- Reconnaissance scanning from a foreign IP
- Brute-force SSH attempts on EC2
- Suspicious API calls from unknown regions

### 3. AWS Security Hub for Risk Management
AWS Security Hub was used to analyze security risks across AWS services and provide compliance insights.

#### Example: Listing High-Risk Findings in Security Hub
```bash
aws securityhub get-findings --filters '{"SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}]}'
```
Security Controls Implemented:
- Enabled CIS AWS Benchmark compliance monitoring
- Auto-remediation of misconfigured S3 Buckets
- Integrated AWS Config for compliance tracking

### 4. Network Security & AWS WAF Configuration
To secure network traffic, AWS WAF (Web Application Firewall) was configured to block common attack patterns.

#### Example: Creating an AWS WAF Rule to Block SQL Injection
```json
{
    "Name": "SQLInjectionProtection",
    "MetricName": "SQLInjection",
    "Predicates": [
        {
            "Negated": false,
            "Type": "SqlInjectionMatch",
            "DataId": "string"
        }
    ]
}
```
Network Security Measures Taken:
- VPC with Subnet Segmentation
- Security Groups with Least Privilege
- NACLs for Traffic Filtering
- AWS Shield Advanced for DDoS Protection

### 5. CloudTrail & SIEM Integration
To ensure full visibility, AWS CloudTrail was configured to log all API calls and integrated with a SIEM for correlation.

#### Example: Querying AWS CloudTrail for Unauthorized API Calls
```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UnauthorizedOperation
```
Incident Response Enhancements:
- Enabled CloudWatch Alarms for Suspicious Activity
- Configured Real-time Alerts for Unauthorized Access
- Integrated Logs into SIEM for Advanced Threat Analysis

### 6. Penetration Testing & Security Validation
To test AWS security controls, penetration testing was conducted using Kali Linux.

#### Example: Scanning Open Ports on an AWS Instance
```bash
nmap -sV -T4 ec2-XX-XX-XX-XX.compute.amazonaws.com
```

#### Example: Brute Force Attack Simulation on AWS SSH
```bash
hydra -L users.txt -P passwords.txt ssh://ec2-XX-XX-XX-XX.compute.amazonaws.com
```
Testing Outcomes:
- IAM Role Policies prevented privilege escalation.
- WAF successfully blocked SQL injection attempts.
- GuardDuty detected brute force attack attempts in real-time.

## Conclusion
The project demonstrated best practices for securing AWS environments by implementing IAM security, threat detection, network security, and SIEM logging. By continuously monitoring threats and automating security compliance, organizations can minimize risks and improve cloud security posture.

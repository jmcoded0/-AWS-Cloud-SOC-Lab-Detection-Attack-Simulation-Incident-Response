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
    subnet_id = subnet_response['Subnet']['SubnetId']
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
rtb_id = rtb_response['RouteTable']['RouteTableId']
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

Update your region and security group name:

```python
# ~/AWS-Cloud-SOC-Lab/scripts/config.py

REGION = "us-east-1"
SECURITY_GROUP_NAME = "coded-sg-v2"
```
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_03_33_53" src="https://github.com/user-attachments/assets/b633d742-eed1-43d8-acce-0754cd19b44f" />

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
<img width="1920" height="909" alt="VirtualBox_Kali Linux_27_07_2025_03_30_22" src="https://github.com/user-attachments/assets/0658e869-30f4-4ca7-911b-c729c6048d74" />

---

### 💻 Step 3: Run the Script

Make sure your virtual environment is active, then run:

```bash
cd ~/AWS-Cloud-SOC-Lab
source .venv/bin/activate
python scripts/create_security_group.py
```

---

### ✅ Output

```
[+] Created Security Group: coded-sg-v2 (ID: sg-0fbe34acc7edebd3e)
[+] Added ALL traffic rule (for lab testing only)
```
<img width="1920" height="392" alt="image" src="https://github.com/user-attachments/assets/b37e459d-6b62-467c-86b4-469088c0f6af" />

---

### 🔍 Optional: Find Your Default VPC ID

If you're not sure what your default VPC ID is, use:

```bash
aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query "Vpcs[*].VpcId" --output text
```

---

✅ **Status:** Security group created and configured successfully.

🧠 **Why this matters:** This group will be used when launching EC2 instances like the **CloudTrail Attacker**, allowing all traffic so you can capture events clearly in logs.

**Next Up → Phase 2: Deploy EC2 instances into this custom VPC and configure GuardDuty monitoring.**

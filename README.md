<p align="center">
  <img src="logo.png" width="256" height="256">
</p>

<h1 align="center">Patrolaroid</h1>

<br/>

Patrolaroid is an instant camera for capturing cloud workload risks. It’s a prod-friendly scanner that makes finding security issues in AWS instances less annoying and disruptive for software engineers and cloud admins. 

Patrolaroid scans production infrastructure from a safe distance rather than within production, so you don’t have to install an agent, run code, or perform other invasive infosec rituals to use it.

## Overview
Patrolaroid snapshots AWS instances to uncover malware, backdoors, cryptominers, toolkits, and other attacker tomfoolery that you probably don’t want in your prod. Software engineers, security engineers, and cloud administrators only need familiarity with YARA and the AWS Management Console to use it. 

Patrolaroid does not require running an agent or code in prod, only needs read-only access to cloud assets, and generally avoids the myriad stability and performance sins of security tools. 

## Why?
### The tired way
Most commercial “cloud security” scanners that aim to detect malware in cloud workloads ironically operate pretty similarly to malware. Their mode of operation is:
1.	Just-in-time installation of an agent via SSH
2.	Running the agent from `/tmp`
3.	Deleting themselves once the scan completes

This results in the security agent stealing compute cycles and I/O from the host it’s scanning, which is veritably unstonkly – as is the chance that prod is borked if the agent screws up.

### The inspired way
Patrolaroid avoids these problems by scanning prod instances for security problems while staying safely out of prod. After the engineer or admin identifies the AWS account containing the instances they want to scan, Patrolaroid then:
1.	Runs from an AWS instance within the same account as the target instances
2.	Snapshots each instance
3.	Uses [YARA rules](https://github.com/rpetrich/patrolaroid/tree/main/rules) to scan the instance’s filesystem for matches (and generates an alert if there is a match)
4.	Deletes the snapshot volume

In short, Patrolaroid provides "point-and-shoot" malware scanning of AWS instances without the malware-like tactics of existing “cloud security” tools. 


# Getting Started with Patrolaroid

All you need is an AWS account and the ability to create an AWS role and EC2 instance to get Patrolaroid up and running. Getting started involves creating a dedicated EC2 instance for Patrolaroid in the same AWS account and availability zones as the EBS volumes you want to scan.

## Step 1: Create an AWS role
:cloud: Make sure to use the account and availability zone you want to scan to create the role :cloud:
1. Log into your AWS account and access the Identity and Access Management (IAM) service in the AWS Management Console, then choose [**Create Role**](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-service.html) (you can also use the AWS CLI if you prefer)
2. Select **AWS service** for type of trusted entity
3. Select **EC2** as the allowed service and use case, then choose **Next: Permissions**
4. Select the [**AmazonEC2FullAccess**](https://console.aws.amazon.com/iam/home?region=us-east-1#/policies/arn%3Aaws%3Aiam%3A%3Aaws%3Apolicy%2FAmazonEC2FullAccess) policy, then choose **Next: Tags**
5. No tags are needed, so select **Next: Review**
6. Type **Patrolaroid** for the **Role name**
7. Review the role and, if satisfied, choose **Create role**

## Step 2: Create an EC2 instance
:cloud: Make sure you’re still logged into the account you want to scan before proceeding :cloud:
1. Open the [AWS EC2 console](https://console.aws.amazon.com/ec2/), then choose **Launch instance**
2. On the Step 1: Choose an Amazon Machine Image (AMI) page, select **Ubuntu Server 20.04 LTS (HVM), SSD Volume Type**
3. On the Step 2: Choose an Instance Type page, select the **t2.micro** type, then click **Next: Configure Instance Details**
4. For IAM role, select the **Patrolaroid** role you created
5. Click **Review and Launch**

## Step 3: Install dependencies
1. [Connect to your new EC2 instance via SSH](https://docs.aws.amazon.com/quickstarts/latest/vmlaunch/step-2-connect-to-instance.html) (or PuTTY if using Windows)
2. Install `gcc` and other package dependencies by running the command:
```
sudo apt-get install curl git make gcc build-essential
```
3. Download and install `golang` by running:
```
curl -OL https://golang.org/dl/go1.16.4.linux-amd64.tar.gz
```
and then:
```
sudo bash -c 'rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.4.linux-amd64.tar.gz'
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile
sudo chown -R $USER /go
```

## Step 4: Install Patrolaroid
Ensure you are connected to your dedicated EC2 instance and then clone Patrolaroid to it:
```
git clone https://github.com/rpetrich/patrolaroid.git
```
Then build Patrolaroid by running:
```
pushd patrolaroid && make && popd
```

## Step 5: Run Patrolaroid
Navigate to the Patrolaroid directory and start it:
```
cd patrolaroid
sudo ./patrolaroid
```
Enjoy your :cloud: :lock: :camera:
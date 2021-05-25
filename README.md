![patrolaroid-logo-smol](https://user-images.githubusercontent.com/18424886/119518450-831cdf80-bd46-11eb-890b-f8f0faffdd8b.png)

# Patrolaroid
Patrolaroid is an instant camera for capturing cloud workload risks. It’s a prod-friendly scanner that makes finding security issues in AWS instances less annoying and disruptive for software engineers and cloud admins. 

Patrolaroid scans production infrastructure from a safe distance rather than within production, so you don’t have to install an agent, run code, or perform other invasive infosec rituals to use it.

## Overview
Patrolaroid snapshots AWS instances to uncover malware that you probably don’t want in your prod. Software engineers, security engineers, and cloud administrators only need familiarity with YARA and AWS instance IDs to use it. 

Patrolaroid does not require running an agent or code in prod, only needs read-only access, and generally avoids the myriad stability and performance sins of security tools. 

## How it’s different
Most commercial “cloud security” scanners that aim to detect malware in cloud workloads ironically operate pretty similarly to malware. Their mode of operation is:
1.	Just-in-time installation of an agent via SSH
2.	Running the agent from /tmp
3.	Deleting themselves once the scan completes

This results in the security agent stealing compute cycles and I/O from the host it’s scanning, which is veritably unstonkly – as is the chance that prod is borked if the agent screws up.

Patrolaroid avoids these problems by scanning prod instances for security problems while staying safely out of prod. After the engineer or admin provides the ID of the volume they want to scan, Patrolaroid then:
1.	Runs from an AWS instance within the same account as the specified instance
2.	Snapshots the specified instance
3.	Uses [YARA rules]( https://github.com/capsule8/go-yara) to scan the instance’s filesystem for matches (and generates an alert if there is a match)
4.	Deletes the snapshot volume

In short, Patrolaroid provides "point-and-shoot" malware scanning of AWS instances without the malware-like tactics of existing “cloud security” tools. 


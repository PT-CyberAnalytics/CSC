# CSC
Cyberattack Score Calculator (CSC). A tool for calculating the cost of a cyber attack.
This tool is designed to assess the costs incurred by hackers when conducting a successful attack on an organization. 
Before using, you should install fonts in the "fonts" folder.
Or you can use the online version https://pt-cyberanalytics.github.io/CSC/

# Disclaimer
- This tool is not applicable to attacks carried out by state APT groups.
- The cost of a cyberattack is not a static quantity and can change over time, as well as when any changes are made to the attacked System.
- In the case of security analysis services, there is no dependence on the cost of the services provided and the calculation of the cost of a cyber attack using this method.
- All calculations are carried out only according to available information, any hidden factors cannot be taken into account in the calculations.

## Total Values
Here the result of the cyber attack cost will be displayed. It is worth noting that many parameters are calculated taking into account the minimum, average and maximum values, which creates space for the final assessment. By default, you can focus on the average value.

## Basic metrics
Basic metrics include the industry of the attacked company and its information security maturity level, attack start and end dates, and the time of collecting scope and reconnaissance. The attack period is estimated from the first day of the attack.

## Hacker infrastructure
These metrics reflect the costs of tools and resources used by hackers.
If complex hashes were brute-forced en masse, the "Brute-force farms" item is checked. Otherwise, the "Brute-force services" item is filled in, and this metric does not indicate all the passwords obtained, but only those that participated in the assessed vector.
The "Proxy servers" metric is not taken into account if the servers are located in the attacked infrastructure.
The "Paid 0/1-day exploits" metric must be clicked after filling in the "0-day/1-day vulnerabilities" tab.

## 0/1 days
If hackers used exploits for 0/1day vulnerabilities, then you will additionally need to specify their characteristics on the "0-day/1-day vulnerabilities" tab.
In this section, you must specify the number of vulnerabilities for which hackers used exploits as part of an attack on the organization.

"Was a 0-day/1-day exploit used?" If hackers used exploits as part of the attack, then you must set the value to "Yes". Otherwise, you do not need to fill in the data on the "0-day - 1-day" tab.

"Software prevalence level": filled in according to the level of popularity of vulnerable software in information systems:
- Local. Software developed and used within one company or a narrow circle of organizations. Usually, these are custom solutions specific to business. Vulnerabilities in such systems have low market value, since they are difficult to monetize at a broad level. Examples: internal corporate systems, custom ERP systems, software for government agencies, custom applications.
- Narrowly specialized. Software used in specialized industries, such as industry, energy or finance. Has an international distribution, but a limited audience. Vulnerabilities in such systems can be useful for targeted attacks on industries. Examples: SCADA systems, banking software, logistics management systems.
- Regional. Software popular in a certain region or country, often created to meet local requirements or standards. Vulnerabilities are of interest to attackers focused on a specific region. Examples: Bitrix, Webtutor, SAP Business One.
- Widely used. Software used by a large number of organizations and corporate users around the world. Vulnerabilities in such products are valued due to the ability to attack both large corporations and small and medium businesses. Examples: MySQL, Cisco ASA, Vmware ESXi.
- Mass. Software installed on most user devices around the world. Such vulnerabilities are extremely popular, as they allow you to attack a huge number of potential targets. Examples: Chrome, Telegram, MS Office, Zoom.
- System. Operating systems that control user devices. Vulnerabilities in them are the most valuable, as they provide access to the basic level of device control and allow complex attacks to be carried out worldwide. Examples: Windows, Linux, macOS, Android.

"Vulnerability type". Filled in according to the vulnerability class:
- Code execution. For example: RCE, RFI.
- Privilege escalation. For example: SQLi, auth bypass, priv esc.
- Information leak. For example: XXE, inf leak, SSRF.
- Other. For example: XSS.

"Severity level". Filled in according to the vulnerability assessment according to CVSS v4.0.

"Patch availability". If the vendor has released a security update that eliminates the vulnerability used by hackers, then the value must be set to "Yes". The presence of a patch is taken into account at the time of vector implementation.


## Hacker attack chain
The attack chain is a detailed description of the hackers' actions based on the MITRE ATT&CK matrix. To correctly fill out this section in the attack report or security analysis, each effective action must have time stamps (start and end time).

"Tactics" and "Technique": filled in for all documented hacker steps that form successful attack vectors (breaking through the network perimeter, obtaining maximum privileges in the internal infrastructure, implementing events that are unacceptable for the company).

A sequence of similar hacker actions can be combined under one tactic. For example, if hackers consistently executed multiple commands to examine a compromised node or system (id, uname, ifconfig, ip a, whoami, ...), then you don't have to describe each technique in detail, but specify the general tactic "Detection", specify a dash instead of technique and set the time for the sum of these steps.

## Required qualifications
The attacker's qualifications are assessed twice.
When evaluating the vector, it is necessary to evaluate the complexity of each step in accordance with the required qualifications of the attacker:
- Basic. Basic knowledge of cyber attacks is sufficient to use the technique; public exploits or publicly distributed software were used
- Basic+. Basic knowledge of attacks on information systems was sufficient to use the technique, but public exploits had to be modified and refined to increase the effectiveness of the attack.
- Advanced. Complex specialized software, modification and refinement of public exploits, knowledge of post-exploitation techniques, and techniques for bypassing security tools and hiding traces of an attack were required to use the technique.
- Expert. Deep knowledge and skills in conducting cyber attacks, reverse engineering software, knowledge of techniques for bypassing security tools, hiding traces, and the ability to identify zero-day vulnerabilities, independently develop exploits and other software were required to use the technique.

Next, depending on the most difficult step in the vector, it is necessary to evaluate the attacker's skill level by the highest value.
The corresponding value must be specified for the "Attacker Qualification Level" metric.

## Time
"Time (hours)" and "Time (minutes)": initially filled in automatically from preset values ​​for each technique. If the attack report or security analysis specifies a different time frame, this value should be changed.
Important: to obtain more accurate results, you should specify the time of the hacker's active actions. For example, if a hacker launched an infrastructure scan that lasted 7 days, then in the "Time" column you should specify not all 7 days, but only the time it took him to launch and process the scan results.

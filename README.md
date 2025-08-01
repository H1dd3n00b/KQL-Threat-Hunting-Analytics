# KQL-Threat-Hunting
 This repository contains a selection of Kusto Query Language (KQL) queries designed for proactive threat hunting. Aligned with the MITRE ATT&amp;CK framework, these queries are crafted to detect and address potential threats effectively.

# KQL for Defender XDR, Microsoft Sentinel & other Microsoft Solutions

The purpose of this repository is to share KQL queries that can be used by anyone and are understandable. These queries are intended to increase detection coverage through the logs of Microsoft Security products. Not all suspicious activities generate an alert by default, but many of those activities can be made detectable through the logs. These queries include Detection Rules, Hunting Queries and Visualisations. Anyone is free to use the queries.

**Presenting this material as your own is illegal and forbidden. A reference to Github [H1dd3n00b](https://github.com/H1dd3n00b) is much appreciated when sharing or using the content.**

# Credits

[@BertJanCyber](https://twitter.com/BertJanCyber) - The content structure of this repository was adopted from [Bert-Jan's KQL repository](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)

[@cyb3rmik3](https://x.com/cyb3rmik3) - The template utilized for threat detections was inspired by [cyb3rmik3's threat hunting template](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/threat-hunting-template.md)

KQL Queries: While I have authored most of the KQL queries here, it's worth noting that as I gather queries in my daily work, the repository may include contributions from others. I strive to acknowledge and credit the original creators whenever possible.

# KQL Categories

For the sake of clarity and organization, the queries within this repository have been structured into categories in accordance with the MITRE ATT&CK framework. Each category encompasses hunting queries tailored to specific tactics outlined within the MITRE Framework.

## MITRE ATT&CK

| MITRE Enterprise Tactic          | Tactic ID                                             |
|-----------------------|------------------------------------------------|
| Reconnaissance        | [TA0043](https://attack.mitre.org/tactics/TA0043/) |
| Resource Development  | [TA0042](https://attack.mitre.org/tactics/TA0042/) |
| [Initial Access](./Initial%20Access/)        | [TA0001](https://attack.mitre.org/tactics/TA0001/) |
| [Execution](./Execution/)            | [TA0002](https://attack.mitre.org/tactics/TA0002/) |
| Persistence           | [TA0003](https://attack.mitre.org/tactics/TA0003/) |
| [Privilege Escalation](./Privilege%20Escalation/)  | [TA0004](https://attack.mitre.org/tactics/TA0004/) |
| [Defense Evasion](./Defense%20Evasion/)       | [TA0005](https://attack.mitre.org/tactics/TA0005/) |
| [Credential Access](./Credential%20Access/)     | [TA0006](https://attack.mitre.org/tactics/TA0006/) |
| [Discovery](./Discovery/)             | [TA0007](https://attack.mitre.org/tactics/TA0007/) |
| [Lateral Movement](./Lateral%20Movement/)      | [TA0008](https://attack.mitre.org/tactics/TA0008/) |
| [Collection](./Collection/)            | [TA0009](https://attack.mitre.org/tactics/TA0009/) |
| Command and Control   | [TA0011](https://attack.mitre.org/tactics/TA0011/) |
| Exfiltration          | [TA0010](https://attack.mitre.org/tactics/TA0010/) |
| [Impact](./Impact/)                | [TA0040](https://attack.mitre.org/tactics/TA0040/) |



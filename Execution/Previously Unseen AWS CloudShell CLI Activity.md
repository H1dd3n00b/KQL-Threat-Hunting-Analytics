# Previously Unseen AWS CloudShell CLI Activity

### Description

This detection triggers when an AWS CloudShell command deviates from the IAM user’s typical behavior over the past two weeks. A positive match strongly suggests that the alerted entity may be compromised, potentially granting an attacker unauthorized CLI access within the AWS environment

### Microsoft Sentinel
```
let lookback = 14d;
let cutoff = 1h;
let AWSCloudTrailFuncAggregation = view () {
    AWSCloudTrail
    | where UserAgent has_any ("aws-cli", "cloudshell")
    | where UserIdentityType == "IAMUser"
    | where EventName matches regex @"Describe|Export|Get|List"
    | where isnotempty(UserIdentityUserName)
};
let EventNameBaseLinePerUser = AWSCloudTrailFuncAggregation
    | where TimeGenerated between (ago(lookback) .. ago(cutoff))
    | summarize
        AmountOfSuccessfulCommandsLast14Days = countif(isempty(ErrorCode)),
        AmountOfUnsuccessfulCommandsLast14Days = countif(isnotempty(ErrorCode)),
        UniqueSuccessfulCommandsLast14Days = make_set_if(EventName, isempty(ErrorCode)),
        UniqueUnsuccessfulCommandsLast14Days = make_set_if(EventName, isnotempty(ErrorCode))
        by UserIdentityUserName
    | extend
        NumberOfUniqueUnsuccessfulCommandsLast14Days = array_length(UniqueUnsuccessfulCommandsLast14Days),
        NumberOfUniqueSuccessfulCommandsLast14Days = array_length(UniqueSuccessfulCommandsLast14Days)
    | extend UniqueCommandsLast14Days = set_union(UniqueSuccessfulCommandsLast14Days, UniqueUnsuccessfulCommandsLast14Days)
    | where AmountOfSuccessfulCommandsLast14Days >= AmountOfUnsuccessfulCommandsLast14Days
    | where NumberOfUniqueSuccessfulCommandsLast14Days >= NumberOfUniqueUnsuccessfulCommandsLast14Days;
AWSCloudTrailFuncAggregation
| where TimeGenerated between (ago(cutoff) .. now())
| summarize
    AmountOfSuccessfulCommandsLastHour = countif(isempty(ErrorCode)),
    AmountOfUnsuccessfulCommandsLastHour = countif(isnotempty(ErrorCode)),
    UniqueSuccessfulCommandsLastHour = make_set_if(EventName, isempty(ErrorCode)),
    UniqueUnsuccessfulCommandsLastHour = make_set_if(EventName, isnotempty(ErrorCode)),
    FirstTimeCommandsExecuted = min(TimeGenerated),
    LatestTimeCommandsExecuted = max(TimeGenerated)
    by UserIdentityUserName
| extend
    NumberOfUniqueUnsuccessfulCommandsLastHour = array_length(UniqueUnsuccessfulCommandsLastHour),
    NumberOfUniqueSuccessfulCommandsLastHour = array_length(UniqueSuccessfulCommandsLastHour)
| extend UniqueCommandsLastHour = set_union(UniqueSuccessfulCommandsLastHour, UniqueUnsuccessfulCommandsLastHour)
| where AmountOfUnsuccessfulCommandsLastHour >= AmountOfSuccessfulCommandsLastHour
| where NumberOfUniqueUnsuccessfulCommandsLastHour >= NumberOfUniqueSuccessfulCommandsLastHour
| lookup EventNameBaseLinePerUser on UserIdentityUserName
| where AmountOfUnsuccessfulCommandsLastHour >= AmountOfUnsuccessfulCommandsLast14Days or isempty(AmountOfUnsuccessfulCommandsLast14Days)
| extend PreviouslyUnobservedCommands = set_difference(UniqueCommandsLastHour, UniqueCommandsLast14Days)
| extend AmountOfPreviouslyUnobservedCommands = array_length(PreviouslyUnobservedCommands)
| where AmountOfPreviouslyUnobservedCommands > 0
| extend FirstTimeSeenCommands = array_length(set_intersect(PreviouslyUnobservedCommands, UniqueUnsuccessfulCommandsLastHour)) > 0
| where FirstTimeSeenCommands
| project-away *14*, *Last*
```

### MITRE ATT&CK Mapping
- Tactics: Execution
- Technique ID: T1651
- [Cloud Administration Command](https://attack.mitre.org/techniques/T1651/)

---

- Tactics: Execution
- Technique ID: T1059.009
- [Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 01/08/2025    | Initial publish                        |

# Brute Force Exceeding User Failure Threshold

### Description

This detection highlights suspicious increases in failed interactive Azure AD logon attempts by evaluating recent activity against each user’s historical 14-day baseline. An alert is raised when failures exceed the user’s maximum baseline or the standard deviation threshold. To improve fidelity, IP addresses with a history of successful logons are excluded, focusing on new or untrusted sources that may reflect brute force techniques.

### Microsoft Sentinel
```
let CIDRASN = (externaldata (CIDR: string, CIDRASN: int, CIDRASNName: string) ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip'] with (ignoreFirstRecord=true));
let lookback = 14d;
let cutoff = 1h;
let bintime = 1h;
let BruteForceFunction = view () {
    SigninLogs
    | where IsInteractive
    | extend ParsedAuthenticationDetails = parse_json(AuthenticationDetails)
    | extend
        authenticationMethod = tostring(ParsedAuthenticationDetails.[0].authenticationMethod),
        authenticationStepRequirement = tostring(ParsedAuthenticationDetails.[0].authenticationStepRequirement),
        succeeded = tobool(ParsedAuthenticationDetails.[0].succeeded)
    | where authenticationMethod == "Password"
//    | where authenticationStepRequirement == "Primary authentication"
    | evaluate ipv4_lookup(CIDRASN, IPAddress, CIDR, return_unmatched=false)
    | project
        TimeGenerated,
        UserId,
        UserPrincipalName,
        AppDisplayName,
        ResultType,
        authenticationMethod,
        succeeded,
        ResultDescription,
        IPAddress,
        CIDR
};
let HistoricalLegitimateIPRanges = materialize (BruteForceFunction
    | where TimeGenerated between (ago(lookback) .. ago(cutoff))
    | summarize
        SuccessfulLogonAmount = countif(succeeded),
        FailedLogonAmount = countif(not(succeeded))
        by CIDR, UserId
    | extend LegitimateCIDRForUser = iff(SuccessfulLogonAmount > FailedLogonAmount and SuccessfulLogonAmount > 1, true, false)
    | where LegitimateCIDRForUser
    | distinct UserId, CIDR);
let HourlyFailedLogonsPerUserBaseline = BruteForceFunction
    | where TimeGenerated between (ago(lookback) .. ago(cutoff))
    | where succeeded == false
    | summarize FailedLogonPerHourCount = count() by bin(TimeGenerated, bintime), UserId
    | summarize
        FailedLogonMeanAverageBaseline = avg(FailedLogonPerHourCount),
        FailedLogonMaxBaseline = max(FailedLogonPerHourCount),
        FailedLogonStandardDeviationBaseline = stdev(FailedLogonPerHourCount)
        by UserId
    | extend FailedLogonStandardDeviationBaseline = iif(FailedLogonStandardDeviationBaseline < 0.5, 0.5, FailedLogonStandardDeviationBaseline);
BruteForceFunction
| where TimeGenerated between (ago(cutoff) .. now())
| join kind=leftanti HistoricalLegitimateIPRanges on UserId, CIDR
| where succeeded == false
| summarize FailedLogonCountLastHour = count() by bin(TimeGenerated, bintime), UserId
| join kind=innerunique HourlyFailedLogonsPerUserBaseline on UserId
| extend ZScore = (FailedLogonCountLastHour - FailedLogonMeanAverageBaseline) / FailedLogonStandardDeviationBaseline
| where FailedLogonCountLastHour > 10 // sanity check
| where FailedLogonCountLastHour > FailedLogonMaxBaseline or ZScore > 3
| join kind=innerunique (BruteForceFunction
    | where TimeGenerated between (ago(cutoff) .. now())
    | summarize
        FailureResultTypes = make_set(ResultType),
        FailureResultDescription = make_set(ResultDescription),
        AttemptedAppAccess = make_set(AppDisplayName),
        IPsUsed = make_set(IPAddress)
        by UserId, UserPrincipalName)
    on UserId
| summarize arg_max(TimeGenerated, *) by UserId
| project-away *1, *2
| project-reorder TimeGenerated, User*, Fail*
```

### MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique ID: T1110.001
- [Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 30/09/2025    | Initial publish                        |




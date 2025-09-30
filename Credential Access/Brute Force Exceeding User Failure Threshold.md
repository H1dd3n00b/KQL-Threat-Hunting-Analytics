# Password Spray Detected

### Description

This detection highlights suspicious increases in failed interactive Azure AD logon attempts by evaluating recent activity against each user’s historical 14-day baseline. An alert is raised when failures exceed the user’s maximum baseline or the standard deviation threshold. To improve fidelity, IP addresses with a history of successful logons are excluded, focusing on new or untrusted sources that may reflect brute force techniques.

### Microsoft Sentinel
```
let lookback = 14d;
let cutoff = 1h;
let bintime = 1h;
let SuccessCodes = dynamic(["0", "50125", "50140", "70043", "70044"]);
let HistoricalSuccessfulIPLogons = materialize (SigninLogs
    | where TimeGenerated between (ago(lookback) .. ago(cutoff))
    | where IsInteractive
    | where ResultType in (SuccessCodes)
    | distinct UserId, IPAddress);
let BruteForceFunction = view () {
    SigninLogs
    | where IsInteractive
    | where ResultType !in (SuccessCodes)
    | project
        TimeGenerated,
        UserId,
        UserPrincipalName,
        AppDisplayName,
        ResultType,
        ResultDescription,
        IPAddress
};
let HourlyFailedLogonsPerUserBaseline = BruteForceFunction
    | where TimeGenerated between (ago(lookback) .. ago(cutoff))
    | summarize FailedLogonPerHourCount = count() by bin(TimeGenerated, bintime), UserId
    | summarize
        FailedLogonMeanAverageBaseline = avg(FailedLogonPerHourCount),
        FailedLogonMaxBaseline = max(FailedLogonPerHourCount),
        FailedLogonStandardDeviationBaseline = stdev(FailedLogonPerHourCount)
        by UserId
    | extend FailedLogonStandardDeviationBaseline = iif(FailedLogonStandardDeviationBaseline < 0.5, 0.5, FailedLogonStandardDeviationBaseline);
BruteForceFunction
| where TimeGenerated between (ago(cutoff) .. now())
| join kind=leftanti HistoricalSuccessfulIPLogons on IPAddress, UserId
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
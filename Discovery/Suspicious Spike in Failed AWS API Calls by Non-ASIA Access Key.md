# Suspicious Spike in Failed AWS API Calls by Non-ASIA Access Key

### Description

This detection triggers when a non-ASIA AWS access key performs an abnormally high number of failed API calls to sensitive services, deviating from its typical behavior over the past two weeks. This may indicate misuse of credentials, unauthorized automation, or reconnaissance activity.

### Microsoft Sentinel
```
let lookback = 14d;
let cutoff = now();
let bintime = 1h;
let AWSNonASIAKeyFilteringFunction = view () {
    AWSCloudTrail
    | where EventName matches regex @"(? i)^(Describe|Export|Get|List|Create|Put|Update|Modify|Attach|Add|Delete|Remo ve|Detach|Disable|Revoke|Stop|Run|Invoke|Start|Launch|Execute|Switch)"
    | where EventName matches regex @"(? i)Secret|Policy|Key|Token|Credential|Password|Encrypt|Decrypt|Assume|Trail|S napshot|ACL|Security|Group|Bucket|Object"
    | where isnotempty(UserIdentityAccessKeyId)
    | where isnotempty(UserIdentityArn)
    | extend AccessKeyIDPrefix = tostring(extract(@"^([A-Z]{4})", 1, UserIdentityAccessKeyId))
    | where AccessKeyIDPrefix != "ASIA"
};
AWSNonASIAKeyFilteringFunction
| where TimeGenerated between (ago(lookback) .. cutoff)
| make-series
    DistinctDeniedEventCount = count_distinctif(EventName, ErrorCode in ("AccessDenied", "Client.UnauthorizedOperation")),
    TotalDeniedErrorCount = countif(ErrorCode in ("AccessDenied", "Client.UnauthorizedOperation")),
    TotalSuccessfulAPICalls = countif(isempty(ErrorCode)),
    DistinctSuccessfulAPICalls = count_distinctif(EventName, isempty(ErrorCode)),
    TotalAmountOfAPICalls = count() default = 0
    on TimeGenerated
    from ago(lookback) to cutoff step bintime
    by UserIdentityArn, UserIdentityAccessKeyId
| extend
    OutliersScoreDistinctDenied = series_outliers(DistinctDeniedEventCount, "ctukey", int(null), 5, 95),
    OutliersScoreTotalDenied = series_outliers(TotalDeniedErrorCount, "ctukey", int(null), 5, 95)
| mv-expand
    TimeGenerated to typeof (datetime),
    OutliersScoreDistinctDenied to typeof (real),
    OutliersScoreTotalDenied to typeof (real),
    DistinctDeniedEventCount to typeof (real),
    TotalSuccessfulAPICalls to typeof (real),
    TotalDeniedErrorCount to typeof (real),
    DistinctSuccessfulAPICalls to typeof (real),
    TotalAmountOfAPICalls to typeof (real)
| where OutliersScoreDistinctDenied > 1
| where OutliersScoreTotalDenied > 1
| where DistinctDeniedEventCount >= DistinctSuccessfulAPICalls
| extend TotalEventErrorRate = TotalDeniedErrorCount / TotalAmountOfAPICalls
| where TotalEventErrorRate >= 0.5
| extend
    BackwardsTimeWindow = TimeGenerated - bintime,
    ForwardTimeWindow = TimeGenerated + bintime
| join kind=inner (AWSNonASIAKeyFilteringFunction
    | where TimeGenerated between (ago(lookback) .. cutoff)
    | summarize
        DistinctDeniedEventSet = make_set_if(EventName, ErrorCode in ("AccessDenied", "Client.UnauthorizedOperation")),
        DistinctSuccessfulEventSet = make_set_if(EventName, isempty(ErrorCode))
        by bin(TimeGenerated, bintime), UserIdentityArn, UserIdentityAccessKeyId
    | extend
        DistinctDeniedEventSetCount = array_length(DistinctDeniedEventSet),
        DistinctSuccessfulEventSetCount = array_length(DistinctSuccessfulEventSet))
    on UserIdentityArn, UserIdentityAccessKeyId
| where TimeGenerated1 between (BackwardsTimeWindow .. ForwardTimeWindow)
| where DistinctSuccessfulAPICalls == DistinctSuccessfulEventSetCount
| where DistinctDeniedEventCount == DistinctDeniedEventSetCount
| project
    TimeGenerated,
    UserIdentityArn,
    UserIdentityAccessKeyId,
    TotalAmountOfAPICalls,
    TotalSuccessfulAPICalls,
    DistinctSuccessfulAPICalls,
    TotalEventErrorRate,
    DistinctDeniedEventSet,
    DistinctSuccessfulEventSet,
    OutliersScoreDistinctDenied,
    OutliersScoreTotalDenied
| where TimeGenerated between (ago(bintime) .. cutoff)
```

### MITRE ATT&CK Mapping
- Tactics: Discovery
- Technique ID: T1087.004
- [Account Discovery: Cloud Account](https://attack.mitre.org/techniques/T1087/004/)

---

- Tactics: Discovery
- Technique ID: T1580
- [Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)

---

- Tactics: Execution
- Technique ID: T1059.009
- [Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)



### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 01/08/2025    | Initial publish                        |

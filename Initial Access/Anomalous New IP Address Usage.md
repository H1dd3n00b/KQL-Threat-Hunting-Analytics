# Anomalous New IP Address Usage

### Description

This detection identifies anomalous sign in  events where a user is observed using a previously unseen IP address during a recent time window. It builds a probabilistic model based on the historical behavior of each user over the past year, evaluating whether the appearance of a new IP is statistically rare using a decaying weighted anomaly score. This query uses the [detect_anomalous_new_entity_fl()](https://learn.microsoft.com/en-us/kusto/functions-library/detect-anomalous-new-entity-fl?view=microsoft-fabric&tabs=query-defined) function to perform this analysis.

### Microsoft Sentinel
```
let detect_anomalous_new_entity_fl = (T: (*), entityColumnName: string, scopeColumnName: string
    , timeColumnName: string, startTraining: datetime, startDetection: datetime, endDetection: datetime
    , maxEntitiesThresh: int = 200, minTrainingDaysThresh: int = 14, decayParam: real = 0.95, anomalyScoreThresh: real = 0.9) {
    //pre-process the input data by adding standard column names and dividing to datasets
    let timePeriodBinSize = 'day';      // we assume a reasonable bin for time is day, so the probability model is built per that bin size
    let processedData = (
        T
        | extend scope      = column_ifexists(scopeColumnName, '')
        | extend entity     = column_ifexists(entityColumnName, '')
        | extend sliceTime  = todatetime(column_ifexists(timeColumnName, ''))
        | where isnotempty(scope) and isnotempty(entity) and isnotempty(sliceTime)
        | extend dataSet = case(
                       (sliceTime >= startTraining and sliceTime < startDetection),
                       'trainSet'
            ,
                       sliceTime >= startDetection and sliceTime <= endDetection,
                       'detectSet'
            ,
                       'other'
                   )
        | where dataSet in ('trainSet', 'detectSet')
        );
    // summarize the data by scope and entity. this will be used to create a distribution of entity appearances based on first seen data
    let entityData = (
        processedData
        | summarize
            countRowsEntity = count(),
            firstSeenEntity = min(sliceTime),
            lastSeenEntity = max(sliceTime),
            firstSeenSet = arg_min(sliceTime, dataSet)
            by scope, entity
        | extend firstSeenSet = dataSet
        | project-away dataSet
        );
    // aggregate entity data per scope and get the number of entities appearing over time
    let aggregatedCandidateScopeData = (
        entityData
        | summarize
            countRowsScope = sum(countRowsEntity),
            countEntitiesScope = dcount(entity),
            countEntitiesScopeInTrain = dcountif(entity, firstSeenSet == 'trainSet')
            ,
            firstSeenScope = min(firstSeenEntity),
            lastSeenScope = max(lastSeenEntity),
            hasNewEntities = iff(dcountif(entity, firstSeenSet == 'detectSet') > 0, 1, 0)
            by scope
        | extend slicesInTrainingScope = datetime_diff(timePeriodBinSize, startDetection, firstSeenScope)
        | where countEntitiesScopeInTrain <= maxEntitiesThresh
            and slicesInTrainingScope >= minTrainingDaysThresh
            and lastSeenScope >= startDetection
            and hasNewEntities == 1
        );
    let modelData = (
        entityData
        | join kind = inner (aggregatedCandidateScopeData) on scope
        | where firstSeenSet == 'trainSet'
        | summarize
            countAddedEntities = dcount(entity),
            firstSeenScope = min(firstSeenScope),
            slicesInTrainingScope = max(slicesInTrainingScope),
            countEntitiesScope = max(countEntitiesScope)
            by
            scope,
            firstSeenSetOnScope = firstSeenSet,
            firstSeenEntityOnScope = firstSeenEntity
        | extend diffInDays = datetime_diff(timePeriodBinSize, startDetection, firstSeenEntityOnScope)
        | extend decayingWeight = pow(base = decayParam, exponent = diffInDays)
        | extend decayingValue = countAddedEntities * decayingWeight
        | summarize
            newEntityProbability =  round(1 - exp(-1.0 * sum(decayingValue) / max(diffInDays)), 4)
            ,
            countKnownEntities = sum(countAddedEntities),
            lastNewEntityTimestamp = max(firstSeenEntityOnScope),
            slicesOnScope = max(slicesInTrainingScope)
            by scope, firstSeenSetOnScope
        | extend newEntityAnomalyScore = round(1 - newEntityProbability, 4)
        | extend isAnomalousNewEntity = iff(newEntityAnomalyScore >= anomalyScoreThresh, 1, 0)
        );
    let resultsData = (
        processedData
        | where dataSet == 'detectSet'
        | join kind = inner (modelData) on scope
        | join kind = inner (entityData
            | where firstSeenSet == 'detectSet')
            on scope, entity, $left.sliceTime == $right.firstSeenEntity
        | project-away scope1, scope2, entity1
        | where isAnomalousNewEntity == 1 and countRowsEntity <= 10 // Only show IPs with 3 or fewer hits
        | summarize arg_min(sliceTime, *) by scope, entity
        | extend
            anomalyType = strcat('newEntity_', entityColumnName),
            anomalyExplainability = strcat(
                                        'The ',
                                        entityColumnName,
                                        ' ',
                                        entity,
                                        ' wasn\'t seen on ',
                                        scopeColumnName,
                                        ' ',
                                        scope,
                                        ' during the last ',
                                        slicesOnScope,
                                        ' ',
                                        timePeriodBinSize,
                                        's. Previously, ',
                                        countKnownEntities
            ,
                                        ' entities were seen, the last one of them appearing at ',
                                        format_datetime(lastNewEntityTimestamp, 'yyyy-MM-dd HH:mm'),
                                        '.'
                                    )
        | join kind = leftouter (entityData
            | where firstSeenSet == 'trainSet'
            | extend entityFirstSeens = strcat(entity, ' : ', format_datetime(firstSeenEntity, 'yyyy-MM-dd HH:mm'))
            | sort by scope, firstSeenEntity asc
            | summarize anomalyState = make_list(entityFirstSeens) by scope)
            on scope
        | project-away scope1
        );
    resultsData
};
// === Parameter configuration ===
let trainPeriodStart = ago(365d); // 365 days ago
let detectPeriodStart = now() - 1h; // Lookback is set to 1 hour. Adjust this to your desired lookback period, for example change to -30d for the past 30 days.
let endDetection = now(); // Dynamic end
SigninLogs
| invoke detect_anomalous_new_entity_fl(
             entityColumnName = 'IPAddress',         // What you want to track, currently looks for new IPs
             scopeColumnName = 'UserId',           // Could also be 'UserPrincipalName' or hardcoded if global
             timeColumnName = 'TimeGenerated',
             startTraining = trainPeriodStart,
             startDetection = detectPeriodStart,
             endDetection = endDetection,
             maxEntitiesThresh = 200,                // Increased from 60
             minTrainingDaysThresh = 14,
             decayParam = 0.95,
             anomalyScoreThresh = 0.9
         )
//| where ResultType in ("0", "50125", "50140", "70043", "70044") // Uncomment this line to filter for successful sign-ins only from new IP addresses
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1078.004
- [Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 02/06/2025    | Initial publish                        |
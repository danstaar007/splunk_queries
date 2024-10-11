
#########
### SPL to show users that RDP into a machine and then use different credentials to elevate their privileges

index=winevents  (EventCode=4624 OR EventCode=4648)
| rex field=_raw "Account Name:\s+(?<user_name>.*)\s+Account Domain:\s+(?<source_domain>.*)\s+"
| rex field=_raw "Account Whose Credentials Were Used:\s+Account Name:\s+(?<creds_used>.*)\s+Account Domain:\s+(?<target_domain>.*)\s+"
| rex field=_raw "Logon Type:\s+(?<LogonType>\d+)"
| eval EventType=case(EventCode=="4624", "Logon", EventCode=="4648", "Used Different Credentials")
| eval login_type=case(
    LogonType=="2", "Interactive",
    LogonType=="3", "Network",
    LogonType=="4", "Batch",
    LogonType=="5", "Service",
    LogonType=="7", "Unlock",
    LogonType=="8", "NetworkCleartext",
    LogonType=="9", "NewCredentials",
    LogonType=="10", "RemoteInteractive",
    LogonType=="11", "CachedInteractive",
    true(), LogonType
)
| eval different_account=if(EventCode=="4648" AND user_name!=creds_used, "Yes", "No") | where user_name!="-" | rename Target_Server_Name AS target_host host AS source_host
| table _time, source_host, user_name, source_domain, EventType, login_type, creds_used, target_domain, target_host, different_account

### SPL to show users that RDP into a machine and then use different credentials to elevate their privileges
#########
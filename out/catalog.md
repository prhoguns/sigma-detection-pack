# Rule catalog

| Rule | Level | ATT&CK tactic | Technique | SQL | Splunk | KQL |
|---|---|---|---|---|---|---|
| [SSH Root Login Accepted From Non-Private Address](rules/linux/sshd_root_login_from_external.yml) | high | Lateral Movement, Initial Access | T1021.004 | ok | ok | n/a |
| [Service Account Spawned an Interactive Shell via sudo](rules/linux/sudo_to_shell_by_service_account.yml) | high | Privilege Escalation | T1548.003 | ok | ok | n/a |
| [Mimikatz Command Line Keywords](rules/windows/proc_mimikatz_command_line.yml) | critical | Credential Access | T1003.001 | ok | ok | ok |
| [PowerShell Encoded Command Execution](rules/windows/proc_powershell_encoded_command.yml) | high | Execution | T1059.001 | ok | ok | ok |
| [Scheduled Task Created Running From User-Writable Path](rules/windows/sec_scheduled_task_suspicious_path.yml) | medium | Persistence | T1053.005 | ok | ok | n/a |
| [Security Event Log Cleared](rules/windows/sec_security_log_cleared.yml) | high | Defense Evasion | T1070.001 | ok | ok | ok |
| [User Added to Privileged Group](rules/windows/sec_user_added_to_privileged_group.yml) | high | Privilege Escalation, Persistence | T1098 | ok | ok | ok |
| [User Account Created by Unexpected Account](rules/windows/sec_user_created_by_unexpected_account.yml) | medium | Persistence | T1136.001 | ok | ok | ok |
| [Cobalt Strike Default Named Pipe](rules/windows/sysmon_cobalt_strike_named_pipe.yml) | critical | Command And Control | T1071 | ok | ok | n/a |
| [Windows Defender Disabled via Registry](rules/windows/sysmon_defender_disabled_registry.yml) | high | Defense Evasion | T1562.001 | ok | ok | ok |
| [LSASS Memory Access by Non-System Process](rules/windows/sysmon_lsass_access.yml) | high | Credential Access | T1003.001 | ok | ok | n/a |

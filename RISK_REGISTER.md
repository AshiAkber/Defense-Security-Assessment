# Windows Defense Security Assessment - Risk Register

| ID | Potential Risk | Priority | Recommended Action |
|---|---|---|---|
| R1 | Repeated failed login events in authentication logs | Medium | Review timestamps and available login details. Use strong passwords and enable multi-factor authentication where supported. |
| R2 | Missing Windows security updates | Medium | Check Windows Update and install approved security updates. |
| R3 | Windows Defender Firewall status unclear or misconfigured | To be assessed | Review Windows Defender Firewall settings and verify that appropriate firewall rules are enabled. |
| R4 | Routine tasks performed with administrator privileges | Medium | Use a standard user account for everyday tasks and administrator privileges only when necessary. |
| R5 | Sensitive information exposed in log files | High if present | Remove or redact passwords, personal information, access tokens, and other secrets before sharing logs. |
| R6 | Suspicious authentication activity | Medium | Investigate repeated failures using relevant Windows security logs and verify whether the activity is expected. |
| R7 | Python script or generated report missing | Low | Verify that project files exist, run the Python syntax check, and confirm that the JSON report is generated. |

## Review Notes
- Risk priorities are preliminary and must be confirmed through assessment.
- Validate each finding on the Windows system being assessed.
- Record the responsible person, review date, remediation, and retest result.
- Do not publish sensitive logs, passwords, or credentials.
- This project performs basic checks and does not automatically verify every Windows security setting.
- Reassess the risks after corrective actions are completed.

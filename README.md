**CIS for macOS Monterey - Script and Configuration Profile
Remediation**

**INFO:**

Refers to document CIS_Apple_macOS_12.0_Monterey_Benchmark_v1.0.0.pdf,
available at <https://benchmarks.cisecurity.org>

**USAGE:**

Create Extension Attributes using the following scripts:

> **2.5_Audit_List Extension Attribute**
>
> Set as Data Type \"String.\" Reads contents of /Library/Application
> Support/SecurityScoring/org_audit file and records to Jamf Pro
> inventory record.
>
> **2.6_Audit_Count Extension Attribute**
>
> Set as Data Type \"Integer.\" Reads contents of /Library/Application
> Support/SecurityScoring/org_audit file and records count of items to
> Jamf Pro inventory record. Usable with smart group logic
> (2.6_Audit_Count greater than 0) to immediately determine computers
> not in compliance.

Add the following scripts to your Jamf Pro

-   1_Set_Organization_Priorities

-   2_Security_Audit_Compliance

-   3_Security_Remediation

Script **1_Set_Organization_Priorities** will need additional
configuration prior to deployment. You have a choice here to leverage a
Manifest for a custom Config Profile, or use the scripted option. The
Audit and Remediation scripts both look for the configuration profile,
if present they replace any copy in /Library/Application
Support/Security.

These scripts will make every attempt to replace a local file in order
for it to leverage the preferred preferences. In previous versions of
the CIS Benchmarks if a site was not configured properly then the
preferences may never be replaced. By using the manifest and altering
the script slightly the organisations have a much simpler method for
deploying and checking preferences rather than editing a script.

**Script Remediation**

CIS Script Responsibility

\* 1.7 Audit Computer Name

\* 2.1.1 Ensure Bluetooth Is Disabled If No Devices Are Paired

\* 2.2.1 Ensure Set time and date automatically Is Enabled

\* 2.2.2 Ensure time set is within appropriate limits

\* 2.4.1 Ensure Remote Apple Events Is Disabled

\* 2.4.3 Ensure Screen Sharing Is Disabled

\* 2.4.4 Ensure Printer Sharing Is Disabled

\* 2.4.5 Ensure Remote Login Is Disabled

\* 2.4.6 Ensure DVD or CD Sharing Is Disabled

\* 2.4.8 Ensure File Sharing Is Disabled

\* 2.4.9 Ensure Remote Management Is Disabled

\* 2.5.3 Ensure Location Services Is Enabled

\* 2.9 Ensure Power Nap Is Disabled

\* 3.4 Ensure Security Auditing Retention Is Enabled

\* 5.1.2 Ensure System Integrity Protection Status (SIPS) Is Enabled

\* 5.1.5 Ensure Sealed System Volume (SSV) Is Enabled

\* 5.9 Ensure system is set to hibernate

**1_Set_Organization_Priorities**

Admins set organizational compliance for each listed item, which gets
written to plist. The values default to \"true,\" meaning if an
organization wishes to disregard a given item they must set the value to
false by changing the associated comment:

OrgScore1_1=\"true\" or OrgScore1_1=\"false\"

Alternatively use the Jamf Schema file to add a custom schema to a
custom payload of a configuration profile.

**2_Security_Audit_Complaince**

Configure the following variables in the script:

The script writes to /Library/Application
Support/SecurityScoring/org_security_score.plist by default.

-   Create a single Jamf Policy using all three scripts.\
    1_Set_Organization_Priorities - Script Priority: Before\
    2_Security_Audit_Compliance Script Priority: Before\
    3_Security_Remediation - Script Priority: Before\
    2_Security_Audit_Compliance - Script Priority: After\
    Maintenance Payload - Update Inventory

-   Policy: Some recurring trigger to track compliance over time.

**Design Solution Example**

Start by first downloading the Zip File for the Benchmark contents

Expand the Zip file and start by uploading the config profiles, scripts
and ensuring the import worked as expected.

**Configuration Profiles**

CIS Benchmark Custom Values macOS 12

+------------------+-------------------------------+------------------+
| General          | Payload                       | Scope            |
+==================+===============================+==================+
| [Distribution    | Use the Upload function of    | All Computers    |
| Met              | the Jamf Server to Upload     |                  |
| hod]{.underline} | "CIS Benchmark Custom Values  |                  |
|                  | macOS 12.mobileconfig". Type  |                  |
| Automatic        | in its name and set its       |                  |
|                  | Category and Scope.           |                  |
| [Descript        |                               |                  |
| ion]{.underline} | Please check that the Custom  |                  |
|                  | payload has the same contents |                  |
| Contents of "CIS | as the Individual XML Files   |                  |
| Benchmark Custom |                               |                  |
| Values macOS 12  |                               |                  |
| Description"     |                               |                  |
+------------------+-------------------------------+------------------+

CIS Benchmark Energy Saver, Security & Privacy and Login Window macOS 12

+------------------+-------------------------------+------------------+
| General          | Payload                       | Scope            |
+==================+===============================+==================+
| [Distribution    | Use the Upload function of    | All Computers    |
| Met              | the Jamf Server to Upload     |                  |
| hod]{.underline} | "CIS Benchmark Energy Saver,  |                  |
|                  | Security & Privacy and Login  |                  |
| Automatic        | Window macOS                  |                  |
|                  | 12.mobileconfig". Type in its |                  |
| [Descript        | name and set its Category and |                  |
| ion]{.underline} | Scope.                        |                  |
|                  |                               |                  |
| Contents of "CIS |                               |                  |
| Benchmark Energy |                               |                  |
| Saver, Security  |                               |                  |
| & Privacy and    |                               |                  |
| Login Window     |                               |                  |
| macOS 12         |                               |                  |
| Description"     |                               |                  |
+------------------+-------------------------------+------------------+

CIS Benchmark Restrictions macOS 12

+------------------+-------------------------------+------------------+
| General          | Payload                       | Scope            |
+==================+===============================+==================+
| [Distribution    | Use the Upload function of    | All Computers    |
| Met              | the Jamf Server to Upload     |                  |
| hod]{.underline} | "CIS Benchmark Restrictions   |                  |
|                  | macOS 12.mobileconfig". Type  |                  |
| Automatic        | in its name and set its       |                  |
|                  | Category and Scope.           |                  |
| [Descript        |                               |                  |
| ion]{.underline} |                               |                  |
|                  |                               |                  |
| Contents of "CIS |                               |                  |
| Benchmark        |                               |                  |
| Restrictions     |                               |                  |
| macOS 12         |                               |                  |
| Description"     |                               |                  |
+------------------+-------------------------------+------------------+

CIS Benchmarks Password Policy

+------------------+-------------------------------+------------------+
| General          | Payload                       | Scope            |
+==================+===============================+==================+
| [Distribution    | Use the Upload function of    | All Computers    |
| Met              | the Jamf Server to Upload     |                  |
| hod]{.underline} | "CIS Password                 |                  |
|                  | Policy.mobileconfig". Type in |                  |
| Automatic        | its name and set its Category |                  |
|                  | and Scope.                    |                  |
| [Descript        |                               |                  |
| ion]{.underline} |                               |                  |
|                  |                               |                  |
| Contents of "CIS |                               |                  |
| Benchmarks       |                               |                  |
| Password Policy  |                               |                  |
| Description"     |                               |                  |
+------------------+-------------------------------+------------------+

![Application, table Description automatically
generated](/Users/ttyler/Desktop/CIS Benchmarking Screen Grabs/media/image1.png){width="6.263888888888889in"
height="1.4076388888888889in"}

**Scripts**

**PREFERENCES**

Set Preferences by Script

+------------------+-------------------------------+------------------+
| General          | Payload                       | Scope            |
+==================+===============================+==================+
| [Trig            | 1_S                           | All Computers    |
| ger]{.underline} | et_Organization_Priorities.sh |                  |
|                  |                               |                  |
| Recurring        |                               |                  |
| Check-in         |                               |                  |
|                  |                               |                  |
| [Freque          |                               |                  |
| ncy]{.underline} |                               |                  |
|                  |                               |                  |
| Once every week  |                               |                  |
+------------------+-------------------------------+------------------+

Set Preferences using a Configuration Profile

+------------------+-------------------------------+------------------+
| General          | Payload                       | Scope            |
+==================+===============================+==================+
| [Distribution    | Application and Custom        | All Computers    |
| Met              | Settings                      |                  |
| hod]{.underline} |                               |                  |
|                  | Custom Schema, populate as    |                  |
| Automatic        | preferred                     |                  |
+------------------+-------------------------------+------------------+

**AUDIT**

Run Audit Script

+------------------+-------------------------------+------------------+
| General          | Payload                       | Scope            |
+==================+===============================+==================+
| [Trig            | Script:                       | All Computers    |
| ger]{.underline} | 2                             |                  |
|                  | _Security_Audit_Compliance.sh |                  |
| Recurring        |                               |                  |
| Check-in         | Maintenance: Update Inventory |                  |
|                  |                               |                  |
| [Freque          |                               |                  |
| ncy]{.underline} |                               |                  |
|                  |                               |                  |
| Once every week  |                               |                  |
+------------------+-------------------------------+------------------+

**Remediate**

Run Remediation Script

+------------------+-------------------------------+------------------+
| General          | Payload                       | Scope            |
+==================+===============================+==================+
| [Trig            | Script:                       | Smart Group:     |
| ger]{.underline} | 3_Security_Remediation.sh     | 2.6_Audit_Count  |
|                  | (Before)                      | (Extension       |
| Recurring        |                               | Attribute) is    |
| Check-in         | 2                             | Greater than 3   |
|                  | _Security_Audit_Compliance.sh |                  |
| [Freque          | (After)                       |                  |
| ncy]{.underline} |                               |                  |
|                  | Maintenance: Update Inventory |                  |
| Once every week  |                               |                  |
+------------------+-------------------------------+------------------+

![Graphical user interface, application Description automatically
generated](/Users/ttyler/Desktop/CIS Benchmarking Screen Grabs/media/image2.png){width="6.263888888888889in"
height="1.0569444444444445in"}

NOTES:

-   Item \"1.1 Verify all Apple provided software is current\" is
    disabled by default.

-   Item \"2.1.2 Turn off Bluetooth \"Discoverable\" mode when not
    pairing devices - not applicable to 10.9 and higher.\" Starting with
    OS X (10.9) Bluetooth is only set to Discoverable when the Bluetooth
    System Preference is selected. To ensure that the computer is not
    Discoverable do not leave that preference open.

-   Item \"2.6.6 Enable Location Services (Not Scored)\" is disabled by
    default. As of macOS 10.12.2, Location Services cannot be
    enabled/monitored programmatically. It is considered user opt in.

-   Item \"2.6.7 Monitor Location Services Access (Not Scored)\" is
    disabled by default. As of macOS 10.12.2, Location Services cannot
    be enabled/monitored programmatically. It is considered user opt in.

-   Item \"2.7.1 Time Machine Auto-Backup \" is disabled by default.
    Time Machine is typically not used as an Enterprise backup solution

-   Item \"2.7.2 Time Machine Volumes Are Encrypted (Not Scored)\" is
    disabled by default. Time Machine is typically not used as an
    Enterprise backup solution

-   Item \"2.10 Securely delete files as needed (Not Scored)\" is
    disabled by default. With the wider use of FileVault and other
    encryption methods and the growing use of Solid State Drives the
    requirements have changed and the \"Secure Empty Trash\" capability
    has been removed from the GUI.

-   Item \"4.3 Create network specific locations (Not Scored)\" is
    disabled by default.

-   Item "4.4 Ensure HTTP Server Is Disabled" cannot disable the built
    in http server of the MacOS. The script will do its best to kill the
    processes, but the macOS runs an HTTP server by default, locally as
    part of its cups printing service.

-   Item \"5.5 Automatically lock the login keychain for inactivity\" is
    disabled by default.

-   Item \"5.6 Ensure login keychain is locked when the computer
    sleeps\" is disabled by default, end user experience can be impacted
    by this.

-   Item \"5.15 Do not enter a password-related hint (Not Scored)\" is
    disabled by default. Not needed if 6.1.2 Disable \"Show password
    hints\" is enforced.

-   Item \"5.17 Secure individual keychains and items (Not Scored)\" is
    disabled by default.

-   Item \"5.8 Create specialized keychains for different purposes (Not
    Scored)\" is disabled by default.

-   Item \"6.3 Safari disable Internet Plugins for global use (Not
    Scored)\" is disabled by default.

**2_Security_Audit_Compliance**

Run this before and after 3_Security_Remediation to audit the
Remediation Reads the plist at /Library/Application
Support/SecurityScoring/org_security_score.plist. For items prioritized
(listed as \"true,\") the script queries against the current
computer/user environment to determine compliance against each item.

Non-compliant items are recorded at /Library/Application
Support/SecurityScoring/org_audit

**3_Security_Remediation**

Run 3_Security_Audit_Compliance after to audit the Remediation Reads the
plist at /Library/Application
Support/SecurityScoring/org_security_score.plist. For items prioritized
(listed as \"true,\") the script applies recommended remediation actions
for the client/user.

SCORED CIS EXCEPTIONS:

-   Does not implement pwpolicy commands (5.2.1 - 5.2.8), instead we
    examine profiles to detect if a password policy has been applied

-   Audits but does not actively remediate (due to alternate
    profile/policy functionality within Jamf Pro):

```{=html}
<!-- -->
```
-   2.4.4 Disable Printer Sharing

-   2.5.1.1 Enable FileVault, prefer to user experience via a policy and
    then enabling "User adjustment of FileVault options" Computers \>
    Configuration Profiles \> Security and Privacy \> FileVault, from
    the drop down select "Prevent FileVault from being disabled"

-   5.19 System Integrity Protection status

```{=html}
<!-- -->
```
-   Audits but does not remediate (due to requirement to review the
    device)

```{=html}
<!-- -->
```
-   3.4 Control access to audit records

**REMEDIATED USING CONFIGURATION PROFILES:**

The following Configuration profiles are available in mobileconfig and
plist form. If you wish to change a particular setting, edit the plist
in question. Mobileconfigs can be uploaded to Jamf Pro Configuration
Profiles as is and plists can be added to a new Configuration Profile as
Custom Payloads.

**CIS 12 Custom Settings mobileconfig**

> CIS Benchmark Custom Values macOS 12

1.1 Ensure All Apple-provided Software Is Current

1.2 Ensure Auto Update Is Enabled

1.3 Ensure Download New Updates When Available is Enabled

1.4 Ensure Installation of App Update Is Enabled

1.5 Ensure System Data Files and Security Updates Are Downloaded
Automatically Is Enabled

1.6 Ensure Install of macOS Updates Is Enabled

2.1.2 Ensure Show Bluetooth Status in Menu Bar Is Enabled

2.3.2 Ensure Screen Saver Corners Are Secure

2.3.3 Audit Lock Screen and Start Screen Saver Tools

2.4.2 Ensure Internet Sharing Is Disabled

2.4.7 Ensure Bluetooth Sharing Is Disabled

2.4.12 Ensure Media Sharing Is Disabled

2.4.13 Ensure AirPlay Receiver Is Disabled

2.5.5 Ensure Sending Diagnostic and Usage Data to Apple Is Disabled

2.5.6 Ensure Limit Ad Tracking Is Enabled

2.10 Ensure Secure Keyboard Entry terminal.app is Enabled

2.12 Audit Automatic Actions for Optical Media

2.14 Audit Sidecar Settings

3.6 Ensure Firewall Logging Is Enabled and Configured

4.2 Ensure Show Wi-Fi status in Menu Bar Is Enabled

5.1.4 Ensure Library Validation Is Enabled

5.6 Ensure the root Account Is Disabled

6.1.3 Ensure Guest Account Is Disabled

6.1.4 Ensure Guest Access to Shared Folders Is Disabled

6.3 Ensure Automatic Opening of Safe Files in Safari Is Disabled
(Automated)

**CIS 12 LoginWindow Security_and_Privacy ScreenSaver mobileconfig**

CIS Benchmark Security and Login macOS 12

-   2.3.1 Ensure an Inactivity Interval of 20 Minutes Or Less for the
    Screen Saver Is Enabled

-   2.5.1.1 Ensure FileVault Is Enabled

-   2.5.2.1 Ensure Gatekeeper is Enabled

-   2.5.2.2 Ensure Firewall Is Enabled

-   2.5.2.3 Ensure Firewall Stealth Mode Is Enabled

-   2.8 Ensure Wake for Network Access Is Disabled

-   3.1 Ensure Security Auditing Is Enabled

-   3.2 Ensure Security Auditing Flags Are Configured Per Local
    Organizational Requirements

-   3.3 Ensure install.log Is Retained for 365 or More Days and No
    Maximum Size

-   5.1.1 Ensure Home Folders Are Secure

-   5.7 Ensure Automatic Login Is Disabled

-   5.8 Ensure a Password is Required to Wake the Computer From Sleep or
    Screen Saver Is Enabled

-   5.13 Ensure a Login Window Banner Exists

-   6.1.1 Ensure Login Window Displays as Name and Password Is Enabled

-   6.1.2 Ensure Show Password Hints Is Disabled

**CIS 12 Restrictions mobileconfig**

-   CIS Benchmark Restrictions macOS 12

-   2.4.10 Ensure Content Caching Is Disabled

-   2.4.11 Ensure AirDrop Is Disabled

-   2.6.1.1 Audit iCloud Configuration

-   Includes:

    -   Disable preference pane (Not Scored) - Restrictions payload \>
        Preferences \> disable selected items \> iCloud

    -   Disable the use of iCloud password for local accounts (Not
        Scored) - Restrictions payload \> Functionality \> Allow use of
        iCloud password for local accounts (unchecked)

    -   Disable iCloud Back to My Mac (Not Scored) - Restrictions
        payload \> Functionality \> Allow iCloud Back to My Mac
        (unchecked)

    -   Disable iCloud Find My Mac (Not Scored) - Restrictions payload
        \> Functionality \> Allow iCloud Find My Mac (unchecked)

    -   Disable iCloud Bookmarks (Not Scored) - Restrictions payload \>
        Functionality \> Allow iCloud Bookmarks (unchecked)

    -   Disable iCloud Mail (Not Scored) - Restrictions payload \>
        Functionality \> Allow iCloud Mail (unchecked)

    -   Disable iCloud Calendar (Not Scored) - Restrictions payload \>
        Functionality \> Allow iCloud Calendar (unchecked)

    -   Disable iCloud Reminders (Not Scored) - Restrictions payload \>
        Functionality \> Allow iCloud Reminders (unchecked)

    -   Disable iCloud Contacts (Not Scored) - Restrictions payload \>
        Functionality \> Allow iCloud Contacts (unchecked)

    -   Disable iCloud Notes (Not Scored) - Restrictions payload \>
        Functionality \> Allow iCloud Notes (unchecked)

-   2.6.1.2 Audit iCloud Keychain

-   2.6.1.3 Audit iCloud Drive

-   2.6.1.4 Ensure iCloud Drive Document and Desktop Sync is Disabled

-   2.7.1 Ensure Backup Up Automatically is Enabled

-   4.1 Ensure Bonjour Advertising Services Is Disabled

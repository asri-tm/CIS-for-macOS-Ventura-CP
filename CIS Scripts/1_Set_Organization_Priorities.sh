#!/bin/bash

####################################################################################################
#
# Copyright (c) 2020, Jamf, LLC.  All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are met:
#               * Redistributions of source code must retain the above copyright
#                 notice, this list of conditions and the following disclaimer.
#               * Redistributions in binary form must reproduce the above copyright
#                 notice, this list of conditions and the following disclaimer in the
#                 documentation and/or other materials provided with the distribution.
#               * Neither the name of the JAMF Software, LLC nor the
#                 names of its contributors may be used to endorse or promote products
#                 derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY JAMF SOFTWARE, LLC "AS IS" AND ANY
#       EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#       WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#       DISCLAIMED. IN NO EVENT SHALL JAMF SOFTWARE, LLC BE LIABLE FOR ANY
#       DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#       (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#       LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#       ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#       SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
####################################################################################################

# written by Katie English, Jamf October 2016
# updated for 10.12 CIS benchmarks by Katie English, Jamf May 2017
# updated to use configuration profiles by Apple Professional Services, January 2018
# github.com/jamfprofessionalservices
# Updated for 10.13 CIS benchmarks by Erin McDonald, Jamf Jan 2019
# Updated for 10.15 CIS benchmarks by Erin McDonald, Jamf, March 2020
# updated for 10.15 CIS benchmarks by Erin McDonald, Jamf 2020
# updated for macOS 12 CIS benchmarks by Tomos Tyler, D8 Services 2022

# USAGE
# Admins set organizational compliance for each listed item, which gets written to plist.
# Values default to "true," and must be commented to "false" to disregard as an organizational priority.
# Writes to /Library/Application Support/SecurityScoring/org_security_score.plist by default.

# Create the Scoring file destination directory if it does not already exist

dir="/Library/Application Support/SecurityScoring"

if [[ ! -e "$dir" ]]; then
    mkdir "$dir"
fi

plistlocation="$dir/org_security_score.plist"


##################################################################
############### ADMINS DESIGNATE ORG VALUES BELOW ################
##################################################################

# 1.1 Ensure All Apple-provided Software Is Current
# ok
OrgScore1_1="true"

# 1.2 Ensure Auto Update Is Enabled
# ok
OrgScore1_2="true"

# 1.3 Ensure Download New Updates When Available is Enabled
# ok
OrgScore1_3="true"

# 1.4 Ensure Installation of App Update Is Enabled
# ok
OrgScore1_4="true"

# 1.5 Ensure System Data Files and Security Updates Are Downloaded Automatically Is Enabled
# ok
OrgScore1_5="true"

# 1.6 Ensure Install of macOS Updates Is Enabled
# ok
OrgScore1_6="true"

# 1.7 Audit Computer Name
# Validated in script ok
OrgScore1_7="true"

# 2.1.1 Ensure Bluetooth Is Disabled If No Devices Are Paired
# Validated in script ok
OrgScore2_1_1="true"

# 2.1.2 Ensure Show Bluetooth Status in Menu Bar Is Enabled
# ok
OrgScore2_1_2="true"

# 2.10 Ensure Secure Keyboard Entry terminal.app is Enabled
# 
OrgScore2_10="true"

# 2.11 Ensure EFI Version Is Valid and Checked Regularly
# 
OrgScore2_11="true"

# 2.12 Audit Automatic Actions for Optical Media
# NA
OrgScore2_12="true"

# 2.13 Audit Siri Settings
# NA
OrgScore2_13="false"

# 2.14 Audit Sidecar Settings
# Custom Payload
OrgScore2_14="true"

# 2.15 Audit Touch ID and Wallet & Apple Pay Settings
# NA
OrgScore2_15="false"

# 2.16 Audit Notification System Preference Settings
# NA
OrgScore2_16="false"

# 2.17 Audit Passwords System Preference Setting
# NA
OrgScore2_17="false"

# 2.2.1 Ensure Set time and date automatically Is Enabled
# Validated in script ok
OrgScore2_2_1="true"

# 2.2.2 Ensure time set is within appropriate limits
# Auto Sync enabled
OrgScore2_2_2="false"

# 2.3.1 Ensure an Inactivity Interval of 20 Minutes Or Less for the Screen Saver Is Enabled
# Confirmed in Config Profile https://fwd.jamfcloud.com/OSXConfigurationProfiles.html?id=20&o=r
OrgScore2_3_1="true"

# 2.3.2 Ensure Screen Saver Corners Are Secure
# Not Enabled, end user to assign
OrgScore2_3_2="false"

# 2.3.3 Audit Lock Screen and Start Screen Saver Tools
# Not Enabled, end user to assign
OrgScore2_3_3="false"

# 2.4.1 Ensure Remote Apple Events Is Disabled
# Validated in script ok
OrgScore2_4_1="true"

# 2.4.10 Ensure Content Caching Is Disabled
# Validated in Config Profile
OrgScore2_4_10="true"

# 2.4.11 Ensure AirDrop Is Disabled
# No - Currently Enabled
OrgScore2_4_11="true"

# 2.4.12 Ensure Media Sharing Is Disabled
# Using Custom Profile - Fix Audit
OrgScore2_4_12="true"

# 2.4.13 Ensure AirPlay Receiver Is Disabled
# Remdiated actual value Added Custom Profile value
OrgScore2_4_13="true"

# 2.4.2 Ensure Internet Sharing Is Disabled
# Custom Config profile Enforced
OrgScore2_4_2="true"

# 2.4.3 Ensure Screen Sharing Is Disabled
# Validated in script ok
OrgScore2_4_3="true"

# 2.4.4 Ensure Printer Sharing Is Disabled
# Validated in script ok
OrgScore2_4_4="true"

# 2.4.5 Ensure Remote Login Is Disabled
# Validated in script ok
OrgScore2_4_5="true"

# 2.4.6 Ensure DVD or CD Sharing Is Disabled
# Validated in script ok
OrgScore2_4_6="true"

# 2.4.7 Ensure Bluetooth Sharing Is Disabled
# Managed By Custom Profile
OrgScore2_4_7="true"

# 2.4.8 Ensure File Sharing Is Disabled
# Validated in script ok
OrgScore2_4_8="true"

# 2.4.9 Ensure Remote Management Is Disabled
# Validated in script ok
OrgScore2_4_9="true"

# 2.5.1.1 Ensure FileVault Is Enabled
# Jamf Connect Login Window ok
OrgScore2_5_1_1="true"

# 2.5.1.2 Ensure all user storage APFS volumes are encrypted
# Skipped
OrgScore2_5_1_2="false"

# 2.5.1.3 Ensure all user storage CoreStorage volumes are encrypted
# Ok
OrgScore2_5_1_3="true"

# 2.5.2.1 Ensure Gatekeeper is Enabled
# ok
OrgScore2_5_2_1="true"

# 2.5.2.2 Ensure Firewall Is Enabled
# ok
OrgScore2_5_2_2="true"

# 2.5.2.3 Ensure Firewall Stealth Mode Is Enabled
# 
OrgScore2_5_2_3="true"

# 2.5.3 Ensure Location Services Is Enabled
# User Config Only
OrgScore2_5_3="true"

# 2.5.4 Audit Location Services Access
# Need to resolve the check to see if LS is enabled or not
OrgScore2_5_4="false"

# 2.5.5 Ensure Sending Diagnostic and Usage Data to Apple Is Disabled
# Ok
OrgScore2_5_5="true"

# 2.5.6 Ensure Limit Ad Tracking Is Enabled
# https://fwd.jamfcloud.com/OSXConfigurationProfiles.html?id=22
OrgScore2_5_6="true"

# 2.5.7 Audit Camera Privacy and Confidentiality
# YES
OrgScore2_5_7="true"

# 2.6.1.1 Audit iCloud Configuration
# YES
OrgScore2_6_1_1="false"

# 2.6.1.2 Audit iCloud Keychain
# YES
OrgScore2_6_1_2="true"

# 2.6.1.3 Audit iCloud Drive
# YES
OrgScore2_6_1_3="true"

# 2.6.1.4 Ensure iCloud Drive Document and Desktop Sync is Disabled
# YES
OrgScore2_6_1_4="true"

# 2.6.2 Audit App Store Password Settings
# 
OrgScore2_6_2="true"

# 2.7.1 Ensure Backup Up Automatically is Enabled
# NA
OrgScore2_7_1="true"

# 2.7.2 Ensure Time Machine Volumes Are Encrypted
# NA
OrgScore2_7_2="false"

# 2.8 Ensure Wake for Network Access Is Disabled
# ok
OrgScore2_8="true"

# 2.9 Ensure Power Nap Is Disabled
# ok
OrgScore2_9="true"

# 3.1 Ensure Security Auditing Is Enabled
# OK
OrgScore3_1="true"

# 3.2 Ensure Security Auditing Flags Are Configured Per Local Organizational Requirements
# Ok
OrgScore3_2="true"

# 3.3 Ensure install.log Is Retained for 365 or More Days and No Maximum Size
# Ok
OrgScore3_3="true"

# 3.4 Ensure Security Auditing Retention Is Enabled
# Ok
OrgScore3_4="true"

# 3.5 Ensure Access to Audit Records Is Controlled
# Ok
OrgScore3_5="true"

# 3.6 Ensure Firewall Logging Is Enabled and Configured
# ok
OrgScore3_6="true"

# 3.7 Audit Software Inventory
# ok
OrgScore3_7="false"

# 4.1 Ensure Bonjour Advertising Services Is Disabled
# Custom
OrgScore4_1="true"

# 4.2 Ensure Show Wi-Fi status in Menu Bar Is Enabled
# ok
OrgScore4_2="true"

# 4.3 Audit Network Specific Locations
# 
OrgScore4_3="false"

# 4.4 Ensure HTTP Server Is Disabled
# ok
OrgScore4_4="true"

# 4.5 Ensure NFS Server Is Disabled
# ok
OrgScore4_5="true"

# 4.6 Audit Wi-Fi Settings
# 
OrgScore4_6="false"

# 5.1.1 Ensure Home Folders Are Secure
# ok
OrgScore5_1_1="true"

# 5.1.2 Ensure System Integrity Protection Status (SIPS) Is Enabled
# Audit Only And Wrong Numbers... in scripts
OrgScore5_1_2="true"

# 5.1.3 Ensure Apple Mobile File Integrity Is Enabled
# ** Work Needed, Compliance done, needs remediation
OrgScore5_1_3="true"

# 5.1.4 Ensure Library Validation Is Enabled
# ** ok
OrgScore5_1_4="true"

# 5.1.5 Ensure Sealed System Volume (SSV) Is Enabled
# ok
OrgScore5_1_5="true"

# 5.1.6 Ensure Appropriate Permissions Are Enabled for System Wide Applications
# ok
OrgScore5_1_6="true"

# 5.1.7 Ensure No World Writable Files Exist in the System Folder
# ok
OrgScore5_1_7="false"

# 5.1.8 Ensure No World Writable Files Exist in the Library Folder
# ok
OrgScore5_1_8="true"

# 5.10 Require an administrator password to access system-wide preferences
# 
OrgScore5_10="true"

# 5.11 Ensure an administrator account cannot login to another user's active and locked session
# 
OrgScore5_11="true"

# 5.12 Ensure a Custom Message for the Login Screen Is Enabled
# Jamf Connect Config Profile
OrgScore5_12="true"

# 5.13 Ensure a Login Window Banner Exists
# 
OrgScore5_13="false"

# 5.14 Ensure Users' Accounts Do Not Have a Password Hint
# 
OrgScore5_14="true"

# 5.15 Ensure Fast User Switching Is Disabled
# 
OrgScore5_15="true"

# 5.2.1 Ensure Password Account Lockout Threshold Is Configured
# 
OrgScore5_2_1="true"

# 5.2.2 Ensure Password Minimum Length Is Configured
# 
OrgScore5_2_2="true"

# 5.2.3 Ensure Complex Password Must Contain Alphabetic Characters Is Configured
# 
OrgScore5_2_3="true"

# 5.2.4 Ensure Complex Password Must Contain Numeric Character Is Configured
# 
OrgScore5_2_4="true"

# 5.2.5 Ensure Complex Password Must Contain Special Character Is Configured
# 
OrgScore5_2_5="true"

# 5.2.6 Ensure Complex Password Must Contain Uppercase and Lowercase Characters Is Configured
# 
OrgScore5_2_6="true"

# 5.2.7 Ensure Password Age Is Configured
# 
OrgScore5_2_7="true"

# 5.2.8 Ensure Password History Is Configured
# 
OrgScore5_2_8="true"

# 5.3 Ensure the Sudo Timeout Period Is Set to Zero
# Custom 2.9 10.12
OrgScore5_3="true"

# 5.4 Ensure a Separate Timestamp Is Enabled for Each User/tty Combo
# 
OrgScore5_4="true"

# 5.5 Ensure login keychain is locked when the computer sleeps
# 
OrgScore5_5="true"

# 5.6 Ensure the root Account Is Disabled
# 
OrgScore5_6="true"

# 5.7 Ensure Automatic Login Is Disabled
# 
OrgScore5_7="true"

# 5.8 Ensure a Password is Required to Wake the Computer From Sleep or Screen Saver Is Enabled
# 
OrgScore5_8="true"

# 5.9 Ensure system is set to hibernate
# 
OrgScore5_9="true"

# 6.1.1 Ensure Login Window Displays as Name and Password Is Enabled
# 
OrgScore6_1_1="true"

# 6.1.2 Ensure Show Password Hints Is Disabled
# 
OrgScore6_1_2="true"

# 6.1.3 Ensure Guest Account Is Disabled
# 
OrgScore6_1_3="true"

# 6.1.4 Ensure Guest Access to Shared Folders Is Disabled
# 
OrgScore6_1_4="true"

# 6.1.5 Ensure the Guest Home Folder Does Not Exist
# 
OrgScore6_1_5="true"

# 6.2 Ensure Show All Filename Extensions Setting is Enabled  
# 
OrgScore6_2="true"

# 6.3 Ensure Automatic Opening of Safe Files in Safari Is Disabled (Automated)
# 
OrgScore6_3="true"

# 7.1 Extensible Firmware Interface (EFI) password (Manual) 
# 
OrgScore7_1="false"

# 7.2 FileVault and Local Account Password Reset using AppleID
# 
OrgScore7_2="false"


##################################################################
############# DO NOT MODIFY ANYTHING BELOW THIS LINE #############
##################################################################
# Write org_security_score values to local plist

cat << EOF > "$plistlocation"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>OrgScore1_1</key>
<${OrgScore1_1}/>
<key>OrgScore1_2</key>
<${OrgScore1_2}/>
<key>OrgScore1_3</key>
<${OrgScore1_3}/>
<key>OrgScore1_4</key>
<${OrgScore1_4}/>
<key>OrgScore1_5</key>
<${OrgScore1_5}/>
<key>OrgScore1_6</key>
<${OrgScore1_6}/>
<key>OrgScore1_7</key>
<${OrgScore1_7}/>
<key>OrgScore2_1_1</key>
<${OrgScore2_1_1}/>
<key>OrgScore2_1_2</key>
<${OrgScore2_1_2}/>
<key>OrgScore2_10</key>
<${OrgScore2_10}/>
<key>OrgScore2_11</key>
<${OrgScore2_11}/>
<key>OrgScore2_12</key>
<${OrgScore2_12}/>
<key>OrgScore2_13</key>
<${OrgScore2_13}/>
<key>OrgScore2_14</key>
<${OrgScore2_14}/>
<key>OrgScore2_15</key>
<${OrgScore2_15}/>
<key>OrgScore2_16</key>
<${OrgScore2_16}/>
<key>OrgScore2_17</key>
<${OrgScore2_17}/>
<key>OrgScore2_2_1</key>
<${OrgScore2_2_1}/>
<key>OrgScore2_2_2</key>
<${OrgScore2_2_2}/>
<key>OrgScore2_3_1</key>
<${OrgScore2_3_1}/>
<key>OrgScore2_3_2</key>
<${OrgScore2_3_2}/>
<key>OrgScore2_3_3</key>
<${OrgScore2_3_3}/>
<key>OrgScore2_4_1</key>
<${OrgScore2_4_1}/>
<key>OrgScore2_4_10</key>
<${OrgScore2_4_10}/>
<key>OrgScore2_4_11</key>
<${OrgScore2_4_11}/>
<key>OrgScore2_4_12</key>
<${OrgScore2_4_12}/>
<key>OrgScore2_4_13</key>
<${OrgScore2_4_13}/>
<key>OrgScore2_4_2</key>
<${OrgScore2_4_2}/>
<key>OrgScore2_4_3</key>
<${OrgScore2_4_3}/>
<key>OrgScore2_4_4</key>
<${OrgScore2_4_4}/>
<key>OrgScore2_4_5</key>
<${OrgScore2_4_5}/>
<key>OrgScore2_4_6</key>
<${OrgScore2_4_6}/>
<key>OrgScore2_4_7</key>
<${OrgScore2_4_7}/>
<key>OrgScore2_4_8</key>
<${OrgScore2_4_8}/>
<key>OrgScore2_4_9</key>
<${OrgScore2_4_9}/>
<key>OrgScore2_5_1_1</key>
<${OrgScore2_5_1_1}/>
<key>OrgScore2_5_1_2</key>
<${OrgScore2_5_1_2}/>
<key>OrgScore2_5_1_3</key>
<${OrgScore2_5_1_3}/>
<key>OrgScore2_5_2_1</key>
<${OrgScore2_5_2_1}/>
<key>OrgScore2_5_2_2</key>
<${OrgScore2_5_2_2}/>
<key>OrgScore2_5_2_3</key>
<${OrgScore2_5_2_3}/>
<key>OrgScore2_5_3</key>
<${OrgScore2_5_3}/>
<key>OrgScore2_5_4</key>
<${OrgScore2_5_4}/>
<key>OrgScore2_5_5</key>
<${OrgScore2_5_5}/>
<key>OrgScore2_5_6</key>
<${OrgScore2_5_6}/>
<key>OrgScore2_5_7</key>
<${OrgScore2_5_7}/>
<key>OrgScore2_6_1_1</key>
<${OrgScore2_6_1_1}/>
<key>OrgScore2_6_1_2</key>
<${OrgScore2_6_1_2}/>
<key>OrgScore2_6_1_3</key>
<${OrgScore2_6_1_3}/>
<key>OrgScore2_6_1_4</key>
<${OrgScore2_6_1_4}/>
<key>OrgScore2_6_2</key>
<${OrgScore2_6_2}/>
<key>OrgScore2_7_1</key>
<${OrgScore2_7_1}/>
<key>OrgScore2_7_2</key>
<${OrgScore2_7_2}/>
<key>OrgScore2_8</key>
<${OrgScore2_8}/>
<key>OrgScore2_9</key>
<${OrgScore2_9}/>
<key>OrgScore3_1</key>
<${OrgScore3_1}/>
<key>OrgScore3_2</key>
<${OrgScore3_2}/>
<key>OrgScore3_3</key>
<${OrgScore3_3}/>
<key>OrgScore3_4</key>
<${OrgScore3_4}/>
<key>OrgScore3_5</key>
<${OrgScore3_5}/>
<key>OrgScore3_6</key>
<${OrgScore3_6}/>
<key>OrgScore3_7</key>
<${OrgScore3_7}/>
<key>OrgScore4_1</key>
<${OrgScore4_1}/>
<key>OrgScore4_2</key>
<${OrgScore4_2}/>
<key>OrgScore4_3</key>
<${OrgScore4_3}/>
<key>OrgScore4_4</key>
<${OrgScore4_4}/>
<key>OrgScore4_5</key>
<${OrgScore4_5}/>
<key>OrgScore4_6</key>
<${OrgScore4_6}/>
<key>OrgScore5_1_1</key>
<${OrgScore5_1_1}/>
<key>OrgScore5_1_2</key>
<${OrgScore5_1_2}/>
<key>OrgScore5_1_3</key>
<${OrgScore5_1_3}/>
<key>OrgScore5_1_4</key>
<${OrgScore5_1_4}/>
<key>OrgScore5_1_5</key>
<${OrgScore5_1_5}/>
<key>OrgScore5_1_6</key>
<${OrgScore5_1_6}/>
<key>OrgScore5_1_7</key>
<${OrgScore5_1_7}/>
<key>OrgScore5_1_8</key>
<${OrgScore5_1_8}/>
<key>OrgScore5_10</key>
<${OrgScore5_10}/>
<key>OrgScore5_11</key>
<${OrgScore5_11}/>
<key>OrgScore5_12</key>
<${OrgScore5_12}/>
<key>OrgScore5_13</key>
<${OrgScore5_13}/>
<key>OrgScore5_14</key>
<${OrgScore5_14}/>
<key>OrgScore5_15</key>
<${OrgScore5_15}/>
<key>OrgScore5_2_1</key>
<${OrgScore5_2_1}/>
<key>OrgScore5_2_2</key>
<${OrgScore5_2_2}/>
<key>OrgScore5_2_3</key>
<${OrgScore5_2_3}/>
<key>OrgScore5_2_4</key>
<${OrgScore5_2_4}/>
<key>OrgScore5_2_5</key>
<${OrgScore5_2_5}/>
<key>OrgScore5_2_6</key>
<${OrgScore5_2_6}/>
<key>OrgScore5_2_7</key>
<${OrgScore5_2_7}/>
<key>OrgScore5_2_8</key>
<${OrgScore5_2_8}/>
<key>OrgScore5_3</key>
<${OrgScore5_3}/>
<key>OrgScore5_4</key>
<${OrgScore5_4}/>
<key>OrgScore5_5</key>
<${OrgScore5_5}/>
<key>OrgScore5_6</key>
<${OrgScore5_6}/>
<key>OrgScore5_7</key>
<${OrgScore5_7}/>
<key>OrgScore5_8</key>
<${OrgScore5_8}/>
<key>OrgScore5_9</key>
<${OrgScore5_9}/>
<key>OrgScore6_1_1</key>
<${OrgScore6_1_1}/>
<key>OrgScore6_1_2</key>
<${OrgScore6_1_2}/>
<key>OrgScore6_1_3</key>
<${OrgScore6_1_3}/>
<key>OrgScore6_1_4</key>
<${OrgScore6_1_4}/>
<key>OrgScore6_1_5</key>
<${OrgScore6_1_5}/>
<key>OrgScore6_2</key>
<${OrgScore6_2}/>
<key>OrgScore6_3</key>
<${OrgScore6_3}/>
<key>OrgScore7_1</key>
<${OrgScore7_1}/>
<key>OrgScore7_2</key>
<${OrgScore7_2}/>
</dict>
</plist>
EOF

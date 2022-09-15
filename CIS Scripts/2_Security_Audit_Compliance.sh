#!/bin/bash

####################################################################################################
#
# Copyright (c) 2017, Jamf, LLC.  All rights reserved.
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
# updated for 10.12 CIS benchmarks by Katie English, Jamf February 2017
# updated to use configuration profiles by Apple Professional Services, January 2018
# updated to use REST API to update EAs instead of recon
# github.com/jamfprofessionalservices
# updated for 10.13 CIS benchmarks by Erin McDonald, Jamf Jan 2019
# updated for 10.15 CIS benchmarks by Erin McDonald, Jamf 2020
# updated for macOS12 CIS Benchmarks by Tomos Tyler, D8 Services 2022

# USAGE
# Reads from plist at /Library/Application Support/SecurityScoring/org_security_score.plist by default.
# For "true" items, runs query for current computer/user compliance.
# Non-compliant items are logged to /Library/Application Support/SecurityScoring/org_audit
# Variables

Defaults="/usr/bin/defaults"


# DO NOT EDIT BELOW THIS LINE
####################################################################################################

plistlocation="/Library/Application Support/SecurityScoring/org_security_score.plist"

configProfileCISPrefs="/Library/Managed Preferences/com.d8services.cispreferences.plist"

auditfilelocation="/Library/Application Support/SecurityScoring/org_audit"
currentUser="$(/usr/bin/stat -f%Su /dev/console)"
hardwareUUID="$(/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | awk -F ": " '{print $2}' | xargs)"

logFile="/Library/Application Support/SecurityScoring/remediation.log"

osVersion="$(sw_vers -productVersion | grep -o '^[0-9]\+')"
if [ "$osVersion" -lt 11 ]; then
	echo "This script does not support an OS lower than Big Sur Please use https://github.com/jamf/CIS-for-macOS-Catalina-CP instead"
	exit 0
fi


if [[ $(tail -n 1 "$logFile") = *"Remediation complete" ]]; then
	echo "Append to existing logFile"
 	echo "$(date -u)" "Beginning Audit" >> "$logFile"
else
 	echo "Create new logFile"
 	echo "$(date -u)" "Beginning Audit" > "$logFile"	
fi

if [[ ! -e $plistlocation ]]&&[[ ! -e ${configProfileCISPrefs} ]]; then
	echo "No scoring file present"
	exit 0
fi

# Check to see if a configuration profile has been pushed down and use that instead.
if [[ -f "${configProfileCISPrefs}" ]];then
	cp "/Library/Managed Preferences/com.d8services.cispreferences.plist" "${plistlocation}"
	echo "Identified Config profile preferences, copying to local path."
	echo "$(date -u)" "Copying Preferences from Configuration Profiles to plist location." > "$logFile"
	exit 0
fi

# Cleanup audit file to start fresh
[ -f "$auditfilelocation" ] && rm "$auditfilelocation"
touch "$auditfilelocation"

# 1.1 Ensure All Apple-provided Software Is Current
# Verify organisational score
Audit1_1="$($Defaults read "$plistlocation" OrgScore1_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit1_1" = "1" ]; then
	countAvailableSUS="$(softwareupdate -l | grep "*" | wc -l | tr -d ' ')"
	# If client fails, then note category in audit file
	if [ "$countAvailableSUS" = "0" ]; then
		echo "$(date -u)" "1.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_1 -bool false; else
		echo "* 1.1 Verify all Apple provided software is current" >> "$auditfilelocation"
		echo "$(date -u)" "1.1 fix" | tee -a "$logFile"
	fi
fi

# 1.2 Enable Auto Update
# Configuration Profile - Custom payload > com.apple.SoftwareUpdate.plist > AutomaticCheckEnabled=true, AutomaticDownload=true
# Verify organisational score
Audit1_2="$($Defaults read "$plistlocation" OrgScore1_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit1_2" = "1" ]; then
	# Check to see if the preference and key exist. If not, write to audit log. Presuming: Unset = not secure state.
	CP_automaticUpdates="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AutomaticCheckEnabled = 1')"
	if [[ "$CP_automaticUpdates" -gt "0" ]]; then
		echo "$(date -u)" "1.2 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_2 -bool false; else
		automaticUpdates="$($Defaults read /Library/Preferences/com.apple.SoftwareUpdate | /usr/bin/grep -c 'AutomaticCheckEnabled = 1')"
		if [[ "$automaticUpdates" -gt "0" ]]; then
			echo "$(date -u)" "1.2 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore1_2 -bool false; else
			echo "* 1.2 Enable Auto Update" >> "$auditfilelocation"
			echo "$(date -u)" "1.2 fix" | tee -a "$logFile"
		fi
	fi
fi

# 1.3 Enable Download new updates when available
# Verify organisational score
Audit1_3=$($Defaults read "$plistlocation" OrgScore1_3)
# If organisational score is 1 or true, check status of client
if [ "$Audit1_3" = "1" ]; then
	# Check to see if the preference and key exist. If not, write to audit log. Presuming: Unset = not secure state.
	CP_automaticAppUpdates=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "AutomaticDownload = 1;" | awk 'NR==1 {print $3+0}')
echo "Audit1_3 value from profile is \"$CP_automaticAppUpdates\""
	if [[ "$CP_automaticAppUpdates" == "1"  ]]; then
		echo "$(date -u)" "1.3 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_3 -bool false
	else
		echo "* 1.3 Enable app update installs" >> "$auditfilelocation"
		echo "$(date -u)" "1.3 fix" | tee -a "$logFile"
	fi
fi

# 1.4 Enable Download new updates when available
# Verify organisational score
Audit1_4="$($Defaults read "$plistlocation" OrgScore1_4)"
# If organisational score is 1 or true, check status of client
if [ "$Audit1_4" = "1" ]; then
	# Check to see if the preference and key exist via config profile
	Cp_AutoInstallAppUdate="$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "AutomaticallyInstallAppUpdates = 1;" | awk 'NR==1 {print $3+0}')"
	if [[ "$Cp_AutoInstallAppUdate" == "1"  ]]; then
		echo "$(date -u)" "1.4 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_4 -bool false
	else
		echo "* 1.4 Check Profile Enable app update installs" >> "$auditfilelocation"
		echo "$(date -u)" "1.4 fix" | tee -a "$logFile"
	fi
fi

# 1.5 Enable system data files and security update installs 
# Configuration Profile - Software Updates - Install security updates automatically and Install xProtect, MRT & Gatekeeper updates automatically (Jamf Pro - Automatically install configuration data and Automatcially install system data files and security updates)
# Verify organisational score
Audit1_5="$($Defaults read "$plistlocation" OrgScore1_5)"
# If organisational score is 1 or true, check status of client
if [ "$Audit1_5" = "1" ]; then
	# Check to see if the preference and key exist. If not, write to audit log. Presuming: Unset = not secure state.
	CP_criticalUpdates="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'ConfigDataInstall = 1')"
	if [[ "$CP_criticalUpdates" -gt "0" ]]; then
		echo "$(date -u)" "1.5 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_5 -bool false; else
		criticalUpdates="$($Defaults read /Library/Preferences/com.apple.SoftwareUpdate | /usr/bin/grep -c 'ConfigDataInstall = 1')"
		if [[ "$criticalUpdates" -gt "0" ]]; then
			echo "$(date -u)" "1.5 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore1_5 -bool false; else
			echo "* 1.5 Enable system data files and security update installs" >> "$auditfilelocation"
			echo "$(date -u)" "1.5 fix" | tee -a "$logFile"
		fi
	fi
fi

# 1.6 Enable OS X update installs 
# Configuration Profile - Software Updates - Automatically install macOS updates
# Verify organisational score
Audit1_6="$($Defaults read "$plistlocation" OrgScore1_6)"
# If organisational score is 1 or true, check status of client
if [ "$Audit1_6" = "1" ]; then
	updateRestart="$($Defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates)"
	# If client fails, then note category in audit file
	if [ "$updateRestart" = "1" ]; then
		echo "$(date -u)" "1.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_6 -bool false; else
		echo "* 1.6 Enable OS X update installs" >> "$auditfilelocation"
		echo "$(date -u)" "1.6 fix" | tee -a "$logFile"
	fi
fi

# 1.7 Audit Computer Name 
# Verify organisational score
Audit1_7="$(defaults read "$plistlocation" OrgScore1_7)"
# If organisational score is 1 or true, check status of client
if [ "$Audit1_7" = "1" ]; then
	currentHostName=`scutil --get ComputerName`
	serialNumber=$(system_profiler SPHardwareDataType | awk '/Serial Number/{print $4}')

	# If client fails, then note category in audit file
	if [[ "${currentHostName}" == "${serialNumber}" ]]; then
		echo "$(date -u)" "1.7 passed" | tee -a "$logFile"
		defaults write "$plistlocation" OrgScore1_7 -bool false
		else
			echo "* 1.7 Audit Computer Name" >> "$auditfilelocation"
			echo "$(date -u)" "1.7 fix" | tee -a "$logFile"
		fi
fi

# 2.1.1 Turn off Bluetooth, if no paired devices exist
# Verify organisational score
Audit2_1_1="$($Defaults read "$plistlocation" OrgScore2_1_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_1_1" = "1" ]; then
	btPowerState="$($Defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState)"
	# If client fails, then note category in audit file
	if [ "$btPowerState" = "0" ]; then
		echo "$(date -u)" "2.1.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_1_1 -bool false; else
		connectable="$(system_profiler SPBluetoothDataType 2>&1| grep Connectable | awk '{print $2}' | head -1)"
		if [[ "$connectable" != "Yes" ]]; then
			echo "$(date -u)" "2.1.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_1_1 -bool false; else
			echo "* 2.1.1 Turn off Bluetooth, if no paired devices exist" >> "$auditfilelocation"
			echo "$(date -u)" "2.1.1 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.1.2 Show Bluetooth status in menu bar
# Verify organisational score
Audit2_1_2="$($Defaults read "$plistlocation" OrgScore2_1_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_1_2" = "1" ]; then
    BT_MenuCheck=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep 'Bluetooth = 18' | awk '{print $3+0}')
	# If client fails, then note category in audit file
	if [ $BT_MenuCheck = "18" ]; then
		echo "$(date -u)" "2.1.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_1_2 -bool false
		else
		echo "* 2.1.2 Show Bluetooth status in menu bar" >> "$auditfilelocation"
		echo "$(date -u)" "2.1.2 fix" | tee -a "$logFile"
	fi
fi

# 2.10 Enable Secure Keyboard Entry in terminal.app 
# Configuration Profile - Custom payload > com.apple.Terminal > SecureKeyboardEntry=true
# Verify organisational score
Audit2_10="$($Defaults read "$plistlocation" OrgScore2_10)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_10" = "1" ]; then
	CP_secureKeyboard="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SecureKeyboardEntry = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_secureKeyboard" -gt "0" ]] ; then
		echo "$(date -u)" "2.10 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_10 -bool false; else
		secureKeyboard="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.Terminal SecureKeyboardEntry)"
		iTermSecure="$($Defaults read -app iTerm 'Secure Input')"
		if [ "$secureKeyboard" = "1" ] && ["$iTermSecure" -ne "0" ]; then
			echo "$(date -u)" "2.10 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_10 -bool false; else
			echo "* 2.10 Enable Secure Keyboard Entry in terminal.app" >> "$auditfilelocation"
			echo "$(date -u)" "2.10 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.11 Ensure EFI version is valid and being regularly checked
# Audit only.  T2 chip Macs do not allow for use of eficheck
# Verify organisational score
Audit2_11="$($Defaults read "$plistlocation" OrgScore2_11)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_11" = "1" ]; then
# Check for T2 chip.  
if system_profiler SPiBridgeDataType | grep 'Model Name:' | grep -q 'T2'; then 
	$Defaults write "$plistlocation" OrgScore2_11 -bool false
	echo "$(date -u)" "2.11 passed" | tee -a "$logFile"
	else
		efiStatus="$(/usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check | grep -c "No changes detected")"
		if [ "$efiStatus" -gt 0 ]; then
			echo "$(date -u)" "2.11 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_11 -bool false
			else
				echo "* 2.11 Ensure EFI version is valid and being regularly checked" >> "$auditfilelocation"
				echo "$(date -u)" "2.11 fix" | tee -a "$logFile"
				fi
fi
fi

# 2.12 Audit Automatic Actions for Optical Media
#
# Verify organisational score
Audit2_12="$($Defaults read "$plistlocation" OrgScore2_12)"
# If organisational score is 1 or true, check status of client

if [ "$Audit2_12" = "1" ]; then
	DigiHub=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "com.apple.digihub"  | awk 'NR==1 {print $3+0}')
	# If client fails, then note category in audit file
	if [[ $DigiHub = "0" ]];then
		echo "$(date -u)" "2.12 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_12 -bool false
	else
		echo "* 2.12 Check The Custom CIS Profile for the deployment of the com.apple.digihub plist" >> "$auditfilelocation"
		echo "$(date -u)" "2.12 fix" | tee -a "$logFile"
	fi
fi

echo "$(date -u)" "2.13 must be User Interactive" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_13 -bool false

# 2.14 Audit Sidecar Settings
# Verify organisational score
Audit2_14="$($Defaults read "$plistlocation" OrgScore2_14)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_14" = "1" ]; then
	SideCarDevices=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "AllowAllDevices" | awk 'NR==1 {print $3+0}')
	SideCarPrefs=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "hasShownPref" | awk 'NR==1 {print $3+0}')
	# If client fails, then note category in audit file
	if [ "$SideCarDevices" == 0 ] && [ "$SideCarPrefs" == 0 ] ; then
		echo "$(date -u)" "2.14 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_14 -bool false
	else
			echo "* 2.14 Check Custom Profile for Sidecar Settings " >> "$auditfilelocation"
			echo "$(date -u)" "2.14 check Restrictions Profile" | tee -a "$logFile"
		fi
fi


# 2.15 Audit Touch ID and Wallet & Apple Pay Settings
# Manual Intervention only
echo "$(date -u)" "2.15 Manual Interaction only" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_15 -bool false

# 2.16 Audit Notification System Preference Settings
# "$(date -u)" "2.16  Not available, Manual Intervention required" | tee -a "$logFile"
echo "$(date -u)" "2.16 Manual Intervention required" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_16 -bool false

# 2.17 Audit Passwords System Preference Setting
echo "$(date -u)" "2.17  Not Check, Password Policy in effect" | tee -a "$logFile"
echo "$(date -u)" "2.17 Config Profile verified" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_17 -bool false

### 2.2.1 Enable "Set time and date automatically" (Not Scored)
# Verify organisational score
Audit2_2_1="$($Defaults read "$plistlocation" OrgScore2_2_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_2_1" = "1" ]; then
	SetTimeAndDateAutomatically="$(systemsetup -getusingnetworktime | awk '{print $3}')"
	# If client fails, then note category in audit file
	if [ "$SetTimeAndDateAutomatically" = "On" ]; then
	 	echo "$(date -u)" "2.2.1 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_2_1 -bool false; else
		echo "* 2.2.1 Enable Set time and date automatically" >> "$auditfilelocation"
		echo "$(date -u)" "2.2.1 fix" | tee -a "$logFile"
	fi
fi

# 2.2.2 Ensure time set is within appropriate limits
# Not audited - time server must be entered in script
# Verify organisational score
Audit2_2_2="$($Defaults read "$plistlocation" OrgScore2_2_2)"
# If organisational score is 1 or true, check status of client
#if [ "$Audit2_2_2" = "1" ]; then

#fi

# 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver 
# Configuration Profile - LoginWindow payload > Options > Start screen saver after: 20 Minutes of Inactivity
# Corrected to look for a profile for the energy saver for user space rather than login window
# Verify organisational score
Audit2_3_1="$($Defaults read "$plistlocation" OrgScore2_3_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_3_1" = "1" ]; then
	# scan for the profile that has the 
	CP_screenSaverTime=$(profiles -P -o stdout | grep "\"Display Sleep Timer\" = 15" | tail -1 | awk '{print $5+0}')
	# If client fails, then note category in audit file
	if [[ "$CP_screenSaverTime" -le "20" ]] && [[ "$CP_screenSaverTime" != "" ]]; then
		echo "$(date -u)" "2.3.1 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_3_1 -bool false; else
		if [[ -f "/Users/$currentUser/Library/Preferences/ByHost/com.apple.screensaver."$hardwareUUID".plist" ]];then
			screenSaverTime="$($Defaults read /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.screensaver."$hardwareUUID".plist idleTime)"
		else
			#Throwing an error here to catch the missing profile
			$screenSaverTime="99999"
		fi
		if [[ "$screenSaverTime" -le "1200" ]] && [[ "$screenSaverTime" != "" ]]; then
			echo "$(date -u)" "2.3.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_3_1 -bool false; else
				echo "* 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver" >> "$auditfilelocation"
				echo "$(date -u)" "2.3.1 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.3.2 Secure screen saver corners 
# Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=5, wvous-bl-corner=0, wvous-tr-corner=0
# Verify organisational score
Audit2_3_2="$($Defaults read "$plistlocation" OrgScore2_3_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_3_2" = "1" ]; then
	CP_corner="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(\"wvous-bl-corner\" =|\"wvous-tl-corner\" =|\"wvous-tr-corner\" =|\"wvous-br-corner\" =)')"
	# If client fails, then note category in audit file
	if [[ "$CP_corner" != *"6"* ]] && [[ "$CP_corner" != "" ]]; then
		echo "$(date -u)" "2.3.2 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_3_2 -bool false; else
		bl_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)"
		tl_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)"
		tr_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)"
		br_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)"
		if [[ "$bl_corner" != "6" ]] && [[ "$tl_corner" != "6" ]] && [[ "$tr_corner" != "6" ]] && [[ "$br_corner" != "6" ]]; then
			echo "$(date -u)" "2.3.2 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_3_2 -bool false; else
			echo "* 2.3.2 Secure screen saver corners" >> "$auditfilelocation"
			echo "$(date -u)" "2.3.2 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.3.3 Familiarize users with screen lock tools or corner to Start Screen Saver 
# Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=5, wvous-bl-corner=0, wvous-tr-corner=0
# Verify organisational score
Audit2_3_3="$($Defaults read "$plistlocation" OrgScore2_3_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_3_3" = "1" ]; then
	# If client fails, then note category in audit file
	CP_corner="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(\"wvous-bl-corner\" =|\"wvous-tl-corner\" =|\"wvous-tr-corner\" =|\"wvous-br-corner\" =)')"
	if [[ "$CP_corner" = *"5"* ]] ; then
		echo "$(date -u)" "2.3.3 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_3_3 -bool false; else
		bl_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)"
		tl_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)"
		tr_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)"
		br_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)"
		if [ "$bl_corner" = "5" ] || [ "$tl_corner" = "5" ] || [ "$tr_corner" = "5" ] || [ "$br_corner" = "5" ]; then
			echo "$(date -u)" "2.3.3 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_3_3 -bool false; else
			echo "* 2.3.3 Familiarize users with screen lock tools or corner to Start Screen Saver" >> "$auditfilelocation"
			echo "$(date -u)" "2.3.3 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.4.1 Disable Remote Apple Events 
# Verify organisational score
Audit2_4_1="$($Defaults read "$plistlocation" OrgScore2_4_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_4_1" = "1" ]; then
	remoteAppleEvents="$(systemsetup -getremoteappleevents | awk '{print $4}')"
	# If client fails, then note category in audit file
	if [ "$remoteAppleEvents" = "Off" ]; then
	 	echo "$(date -u)" "2.4.1 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_1 -bool false; else
		echo "* 2.4.1 Disable Remote Apple Events" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.1 fix" | tee -a "$logFile"
	fi
fi

# 2.4.10 Disable Content Caching
# Verify organisational score
Audit2_4_10="$($Defaults read "$plistlocation" OrgScore2_4_10)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_4_10" = "1" ]; then
	contentCacheStatus="$(/usr/bin/AssetCacheManagerUtil status 2>&1 | grep -c "Activated: false")"
	# If client fails, then note category in audit file
	if [ "$contentCacheStatus" == 1 ]; then
 		echo "$(date -u)" "2.4.10 passed" | tee -a "$logFile"
 		$Defaults write "$plistlocation" OrgScore2_4_10 -bool false; else
		echo "* 2.4.10 Disable Disable Content Caching" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.10 fix" | tee -a "$logFile"
	fi
fi

# 2.4.11 Ensure AirDrop Is Disabled
# Config profile managed
#echo "$(date -u)" "2.4.11 Restriction Profile Managed" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_4_11 -bool false

# 2.4.12 Ensure Media Sharing Is Disabled
# Adjusted due to error in original file
# Verify organisational score
Audit2_4_12="$($Defaults read "$plistlocation" OrgScore2_4_12)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_4_12" = "1" ]; then
	mediaSharingStatusHome=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep homeSharingUIStatus | awk 'NR {print $3+0}')
	mediaSharingStatusLegacy=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep legacySharingUIStatus | awk 'NR {print $3+0}')
	mediaSharingUIStatus=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep mediaSharingUIStatus | awk 'NR {print $3+0}')
	# If client fails, then note category in audit file
	if [ "$mediaSharingStatusHome" == 0 ] && [ "$mediaSharingStatusLegacy" == 0 ] && [ "$mediaSharingUIStatus" == 0 ]; then
		echo "$(date -u)" "2.4.12 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_4_12 -bool false
	else
			echo "* 2.4.12 Check Custom Profile for Disable Media Sharing" >> "$auditfilelocation"
			echo "$(date -u)" "2.4.12 fix" | tee -a "$logFile"
		fi
fi

# 2.4.13 Ensure AirPlay Receiver Is Disabled
# Config profile managed
#
# Verify organisational score
Audit2_4_13="$($Defaults read "$plistlocation" OrgScore2_4_13)"
# If organisational score is 1 or true, check status of client

if [ "$Audit2_4_13" = "1" ]; then
	airPlay=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "AirplayRecieverEnabled" | awk '{print $3}' | cut -c 1)	# If client fails, then note category in audit file
	if [[ ${airPlay} = "0" ]];then
		echo "$(date -u)" "2.4.13 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_4_13 -bool false
	else
		echo "* 2.4.13 Check Custom CIS Restriction for the key \"com.apple.controlcenter\" and the value \"AirplayRecieverEnabled\"" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.13 fix" | tee -a "$logFile"
	fi
fi

# 2.4.2 Disable Internet Sharing 
# Verify organisational score
Audit2_4_2="$($Defaults read "$plistlocation" OrgScore2_4_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then note category in audit file
if [ "$Audit2_4_2" = "1" ]; then
	if [ -e /Library/Preferences/SystemConfiguration/com.apple.nat.plist ]; then
		natAirport="$(/usr/libexec/PlistBuddy -c "print :NAT:AirPort:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist)"
		natEnabled="$(/usr/libexec/PlistBuddy -c "print :NAT:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist)"
		natPrimary="$(/usr/libexec/PlistBuddy -c "print :NAT:PrimaryInterface:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist)"
        forwarding="$(sysctl net.inet.ip.forwarding | awk '{ print $NF }')"
		if [ "$natAirport" = "true" ] || [ "$natEnabled" = "true" ] || [ "$natPrimary" = "true" ] || [ "$forwarding" = "1" ]; then
			echo "* 2.4.2 Disable Internet Sharing"  >> "$auditfilelocation"
			echo "$(date -u)" "2.4.2 fix" | tee -a "$logFile"
        else
			echo "$(date -u)" "2.4.2 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_4_2 -bool false
		fi
    else
		echo "$(date -u)" "2.4.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_4_2 -bool false
	fi
fi

# 2.4.3 Disable Screen Sharing 
# Verify organisational score
Audit2_4_3="$($Defaults read "$plistlocation" OrgScore2_4_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_4_3" = "1" ]; then
	# If client fails, then note category in audit file
	screenSharing="$(launchctl list | egrep -c screensharing)"
	if [ "$screenSharing" -gt 0 ]; then
		echo "* 2.4.3 Disable Screen Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.3 fix" | tee -a "$logFile"; else
	 	echo "$(date -u)" "2.4.3 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_3 -bool false
	fi
fi

# 2.4.4 Disable Printer Sharing 
# Verify organisational score
Audit2_4_4="$($Defaults read "$plistlocation" OrgScore2_4_4)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_4_4" = "1" ]; then
	# If client fails, then note category in audit file
	printerSharing="$(/usr/sbin/cupsctl | grep -c "share_printers=0")"
	if [ "$printerSharing" != "0" ]; then
	 	echo "$(date -u)" "2.4.4 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_4 -bool false; else
		echo "* 2.4.4 Disable Printer Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.4 fix" | tee -a "$logFile"
	fi
fi

# 2.4.5 Disable Remote Login 
# Verify organisational score
Audit2_4_5="$($Defaults read "$plistlocation" OrgScore2_4_5)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_4_5" = "1" ]; then
	remoteLogin="$(/usr/sbin/systemsetup -getremotelogin | awk '{print $3}')"
	# If client fails, then note category in audit file
	if [ "$remoteLogin" = "Off" ]; then
	 	echo "$(date -u)" "2.4.5 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_5 -bool false; else
		echo "* 2.4.5 Disable Remote Login" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.5 fix" | tee -a "$logFile"
	fi
fi

# 2.4.6 Disable DVD or CD Sharing 
# Verify organisational score
Audit2_4_6="$($Defaults read "$plistlocation" OrgScore2_4_6)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_4_6" = "1" ]; then
	discSharing="$(launchctl list | egrep ODSAgent)"
	# If client fails, then note category in audit file
	if [ "$discSharing" = "" ]; then
	 	echo "$(date -u)" "2.4.6 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_6 -bool false; else
		echo "* 2.4.6 Disable DVD or CD Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.6 fix" | tee -a "$logFile"
	fi
fi


# 2.4.7 Disable Bluetooth Sharing
# Verify organisational score
Audit2_4_7="$($Defaults read "$plistlocation" OrgScore2_4_7)"
# If organisational score is 1 or true, check status of client and user
if [ "$Audit2_4_7" = "1" ]; then
	btSharing="$(/usr/libexec/PlistBuddy -c "print :PrefKeyServicesEnabled"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist)"
	# If client fails, then note category in audit file
	if [ "$btSharing" = "true" ]; then
		echo "* 2.4.7 Disable Bluetooth Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.7 fix" | tee -a "$logFile"; else
	 	echo "$(date -u)" "2.4.7 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_7 -bool false
	fi
fi

# 2.4.8 Disable File Sharing
# Verify organisational score
Audit2_4_8="$($Defaults read "$plistlocation" OrgScore2_4_8)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_4_8" = "1" ]; then
	afpEnabled="$(launchctl list | egrep AppleFileServer)"
	smbEnabled="$(launchctl list | egrep smbd)"
	# If client fails, then note category in audit file
	if [ "$afpEnabled" = "" ] && [ "$smbEnabled" = "" ]; then
 		echo "$(date -u)" "2.4.8 passed" | tee -a "$logFile"
 		$Defaults write "$plistlocation" OrgScore2_4_8 -bool false; else
		echo "* 2.4.8 Disable File Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.8 fix" | tee -a "$logFile"
	fi
fi

# 2.4.9 Disable Remote Management
# Verify organisational score
Audit2_4_9="$($Defaults read "$plistlocation" OrgScore2_4_9)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_4_9" = "1" ]; then
	remoteManagement="$(ps -ef | egrep ARDAgent | grep -c "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent")"
	# If client fails, then note category in audit file
	if [ "$remoteManagement" = "1" ]; then
 		echo "$(date -u)" "2.4.9 passed" | tee -a "$logFile"
 		$Defaults write "$plistlocation" OrgScore2_4_9 -bool false; else
		echo "* 2.4.9 Disable Remote Management" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.9 fix" | tee -a "$logFile"
	fi
fi

# 2.5.1.1 Enable FileVault 
# Verify organisational score
# Audit only.  Does not remediate
Audit2_5_1_1="$($Defaults read "$plistlocation" OrgScore2_5_1_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_5_1_1" = "1" ]; then
	filevaultEnabled="$(fdesetup status | awk '{print $3}')"
	# If client fails, then note category in audit file
	if [ "$filevaultEnabled" = "Off." ]; then
		echo "* 2.5.1.1 Enable FileVault" >> "$auditfilelocation"
		echo "$(date -u)" "2.5.1.1 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "2.5.1.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_1_1 -bool false	
	fi
fi

# 2.5.1.2 Ensure all user storage APFS Volumes are encrypted
# Verify organisational score
# Does not Audit, Jamf PRO Manages encyption of Disks
echo "$(date -u)" "2.5.1.2 Jamf Pro Manages This" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_5_1_2 -bool false

# 2.5.1.3 Ensure all user storage CoreStorage Volumes are encrypted
# Verify organisational score
# Audit only.  Does not remediate
Audit2_5_1_3="$($Defaults read "$plistlocation" OrgScore2_5_1_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_5_1_3" = "1" ]; then
	apfsyes="$(diskutil ap list)"
	if [ "$apfsyes" == "No APFS Containers found" ]; then
		# get Logical Volume Family
		LFV="$(diskutil cs list | grep "Logical Volume Family" | awk '/Logical Volume Family/ {print $5}')"
		# Check encryption status is complete
		EncryptStatus="$( diskutil cs "$LFV" | awk '/Conversion Status/ {print $3}')"
		if [ "$EncryptStatus" != "Complete" ]; then
		echo "* 2.5.1.3 Ensure all user CoreStorage volumes encrypted" >> "$auditfilelocation"
		echo "$(date -u)" "2.5.1.3 fix" | tee -a "$logfile"; else 
		echo "$(date -u)" "2.5.1.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_1_3 -bool false	
		fi
	else 
	echo "$(date -u)" "2.5.1.3 not applicable, APFS storage enabled OK" | tee -a "$logFile"
	fi
fi

# 2.5.2.1 Enable Gatekeeper 
# Configuration Profile - Security and Privacy payload > General > Gatekeeper > Mac App Store and identified developers (selected)
# Verify organisational score
Audit2_5_2_1="$($Defaults read "$plistlocation" OrgScore2_5_2_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_5_2_1" = "1" ]; then
	CP_gatekeeperEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'EnableAssessment = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_gatekeeperEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "2.5.2.1 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_2_1 -bool false; else
		gatekeeperEnabled="$(spctl --status | grep -c "assessments enabled")"
		if [ "$gatekeeperEnabled" = "1" ]; then
			echo "$(date -u)" "2.5.2.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_5_2_1 -bool false; else
			echo "* 2.5.2.1 Enable Gatekeeper" >> "$auditfilelocation"
			echo "$(date -u)" "2.5.2.1 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.5.2.2 Enable Firewall 
# Configuration Profile - Security and Privacy payload > Firewall > Enable Firewall (checked)
# Verify organisational score
Audit2_5_2_2="$($Defaults read "$plistlocation" OrgScore2_5_2_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_5_2_2" = "1" ]; then
	CP_firewallEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'EnableFirewall = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_firewallEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "2.5.2.2 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_2_2 -bool false; else
		firewallEnabled="$($Defaults read /Library/Preferences/com.apple.alf globalstate)"
		if [ "$firewallEnabled" = "0" ]; then
			echo "* 2.5.2.2 Enable Firewall" >> "$auditfilelocation"
			echo "$(date -u)" "2.5.2.2 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "2.5.2.2 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_5_2_2 -bool false
		fi
	fi
fi

# 2.5.2.3 Enable Firewall Stealth Mode 
# Configuration Profile - Security and Privacy payload > Firewall > Enable stealth mode (checked)
# Verify organisational score
Audit2_5_2_3="$($Defaults read "$plistlocation" OrgScore2_5_2_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_5_2_3" = "1" ]; then
	CP_stealthEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'EnableStealthMode = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_stealthEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "2.5.2.3 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_2_3 -bool false; else
		stealthEnabled="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | awk '{print $3}')"
		if [ "$stealthEnabled" = "enabled" ]; then
			echo "$(date -u)" "2.5.2.3 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_5_2_3 -bool false; else
			echo "* 2.5.2.3 Enable Firewall Stealth Mode" >> "$auditfilelocation"
			echo "$(date -u)" "2.5.2.3 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.5.3 Enable Location Services
# Verify organisational score
Audit2_5_3="$($Defaults read "$plistlocation" OrgScore2_5_3)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_5_3" = "1" ]; then
       auditdEnabled=$(launchctl print-disabled system | grep -c '"com.apple.locationd" => true')
       if [ "$auditdEnabled" = "0" ]; then
           echo "$(date -u)" "2.5.3 passed" | tee -a "$logFile"
           $Defaults write "$plistlocation" OrgScore2_5_3 -bool false
       else
           echo "* 2.5.3 Enable Location Services" >> "$auditfilelocation"
           echo "$(date -u)" "2.5.3 fix" | tee -a "$logFile"
       fi
fi

# 2.5.4 Audit Location Services Access
# Manual Interaction needed
echo "$(date -u)" "2.5.4 Manual Intervention required" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_5_4 -bool false

# 2.5.5 Disable sending diagnostic and usage data to Apple
# Verify organisational score
Audit2_5_5="$($Defaults read "$plistlocation" OrgScore2_5_5)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_5_5" = "1" ]; then
	CP_disableDiagnostic="$(/usr/bin/profiles -P -o stdout | grep "allowDiagnoticSubmission" | awk '{print $3}' | cut -c 1)"
	# If client fails, then note category in audit file
	if [[ "$CP_disableDiagnostic" == "0" ]] ; then
		echo "$(date -u)" "2.5.5 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_5 -bool false; else
	AppleDiagn=$($Defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit)
	if [ "$AppleDiagn" == 1 ]; then 
		/bin/echo "* 2.5.5 Disable sending diagnostic and usage data to Apple" >> "$auditfilelocation"
		echo "$(date -u)" "2.5.5 fix Disable sending diagnostic and usage data to Apple" | tee -a "$logFile"; else
		echo "$(date -u)" "2.5.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_5 -bool false
		fi
	fi
fi

# 2.5.6 Limit Ad tracking and personalized Ads
# Verify organisational score
Audit2_5_6="$($Defaults read "$plistlocation" OrgScore2_5_6)"

# If organisational score is 1 or true, check status of client
if [ "$Audit2_5_6" = "1" ]; then
		AdTracking=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "forceLimitAdTracking = 1" | awk '{print $3}' | cut -c 1)
	PersonalAds=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "allowApplePersonalizedAdvertising = 0" | awk '{print $3}' | cut -c 1)
	if [[ $AdTracking = "1" ]]&&[[ $PersonalAds = "0" ]]; then
		echo "$(date -u)" "2.5.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_6 -bool false
	else
		echo "* 2.5.6 Review Limit Ad tracking and personalized Ads" >> "$auditfilelocation"
		echo "$(date -u)" "2.5.6 Please check config profile Custom Payload" | tee -a "$logFile"
	fi
fi

# 2.5.7 Audit Camera Privacy and Confidentiality
# Verify organisational score
Audit2_5_7="$($Defaults read "$plistlocation" OrgScore2_5_7)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_5_7" = "1" ]; then
	cameraAllowed=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "allowCamera" | awk 'NR==1 {print $3+0}')
		# If client fails, then note category in audit file
		# Set the key to 0 (true or disabled) or 1 (false or allowed) based on your organization's preference
		if [ "$cameraAllowed" == 1 ]; then
			echo "$(date -u)" "2.5.7 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_5_7 -bool false
		else
			echo "* 2.5.7 Check Restrictions Profile for Allow Camera" >> "$auditfilelocation"
			echo "$(date -u)" "2.5.7 check Restrictions Profile" | tee -a "$logFile"
		fi
fi

# 2.6.1.1 iCloud configuration (Check for iCloud accounts) (Not Scored)
# Verify organisational score
Audit2_6_1_1="$($Defaults read "$plistlocation" OrgScore2_6_1_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_6_1_1" = "1" ]; then

echo "$(date -u)" "2.6.1.1 See Config Profile" #| tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_6_1_1 -bool false

fi

# 2.6.1.2 Disable iCloud keychain (Not Scored) - 
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
# Verify organisational score
Audit2_6_1_2="$($Defaults read "$plistlocation" OrgScore2_6_1_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_6_1_2" = "1" ]; then
	CP_iCloudKeychain="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudKeychainSync = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_iCloudKeychain" -gt "0" ]] ; then
		echo "$(date -u)" "2.6.1.2 passed CP" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_6_1_2 -bool false; else
		echo "* 2.6.1.2 Disable iCloud Keychain with configuration profile" >> "$auditfilelocation"
		echo "$(date -u)" "2.6.1.2 fix" | tee -a "$logFile"
	fi
fi

# 2.6.1.3 Disable iCloud Drive (Not Scored)
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
# Verify organisational score
Audit2_6_1_3="$($Defaults read "$plistlocation" OrgScore2_6_1_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_6_1_3" = "1" ]; then
	CP_iCloudDrive="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDocumentSync = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_iCloudDrive" -gt "0" ]] ; then
		echo "$(date -u)" "2.6.1.3 passed CP" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_6_1_3 -bool false; else
		echo "* 2.6.1.3 Disable iCloud Drive with configuration profile" >> "$auditfilelocation"
		echo "$(date -u)" "2.6.1.3 fix" | tee -a "$logFile"
	fi
fi

# 2.6.1.4 iCloud Drive Document sync
# Configuration Profile - Restrictions payload - > Functionality > Allow iCloud Desktop & Documents (unchecked)
# Verify organisational score
Audit2_6_1_4="$($Defaults read "$plistlocation" OrgScore2_6_1_4)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_6_1_4" = "1" ]; then
	# If client fails, then note category in audit file
	CP_icloudDriveDocSync="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDesktopAndDocuments = 0')"
	if [[ "$CP_icloudDriveDocSync" -gt "0" ]] ; then
		echo "$(date -u)" "2.6.1.4 passed CP" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_6_1_4 -bool false; else
		echo "* 2.6.1.4 Disable iCloud Drive Document sync with configuration profile" >> "$auditfilelocation"
		echo "$(date -u)" "2.6.1.4 fix" | tee -a "$logFile"
	fi
fi

# 2.6.1.4 iCloud Drive Desktop sync
# Configuration Profile - Restrictions payload - > Functionality > Allow iCloud Desktop & Documents (unchecked)
# Verify organisational score
Audit2_6_1_4="$($Defaults read "$plistlocation" OrgScore2_6_1_4)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_6_1_4" = "1" ]; then
	# If client fails, then note category in audit file
	CP_icloudDriveDocSync="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDesktopAndDocuments = 0')"
	if [[ "$CP_icloudDriveDocSync" -gt "0" ]] ; then
		echo "$(date -u)" "2.6.1.4 passed CP" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_6_1_4 -bool false; else
		echo "* 2.6.1.4 Disable iCloud Drive Desktop sync with configuration profile" >> "$auditfilelocation"
		echo "$(date -u)" "2.6.1.4 fix" | tee -a "$logFile"
	fi
fi

# 2.6.2 Audit App Store Password Settings
# Manual Intereaction needed
echo "$(date -u)" "2.6.2 Manual Intervention required" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_6_2 -bool false

# 2.7.1 Time Machine Auto-Backup
# Verify organisational score
Audit2_7_1="$($Defaults read "$plistlocation" OrgScore2_7_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_7_1" = "1" ]; then
	timeMachineAuto="$( $Defaults read /Library/Preferences/com.apple.TimeMachine.plist AutoBackup )"
	# If client fails, then note category in audit file
	if [ "$timeMachineAuto" != "1" ]; then
		echo "* 2.7.1 Time Machine Auto-Backup" >> "$auditfilelocation"
		echo "$(date -u)" "2.7.1 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "2.7.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_7_1 -bool false
	fi
fi

# 2.7.2 Ensure Time Machine Volumes Are Encrypted
# Not managed as Time Machine is not a corporate product
echo "$(date -u)" "2.7.2 Not a Corporate product" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore2_7_2 -bool false

# 2.8 Disable "Wake for network access"
# Verify organisational score
Audit2_8="$($Defaults read "$plistlocation" OrgScore2_8)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_8" = "1" ]; then
	CP_wompEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '"Wake On LAN" = 0')"
		# If client fails, then note category in audit file
		if [[ "$CP_wompEnabled" = "3" ]] ; then
			echo "$(date -u)" "2.8 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_8 -bool false; else
			wompEnabled="$(pmset -g | grep womp | awk '{print $2}')"
			if [ "$wompEnabled" = "0" ]; then
				echo "$(date -u)" "2.8 passed" | tee -a "$logFile"
				$Defaults write "$plistlocation" OrgScore2_8 -bool false; else
				echo "* 2.8 Disable Wake for network access" >> "$auditfilelocation"
				echo "$(date -u)" "2.8 fix" | tee -a "$logFile"
			fi
		fi
fi

# 2.9 Disable Power Nap
# Verify organisational score
Audit2_9="$($Defaults read "$plistlocation" OrgScore2_9)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_9" = "1" ]; then
	napEnabled="$(pmset -g everything | grep -c 'powernap             1')"
	if [ "$napEnabled" = 0 ]; then
		echo "$(date -u)" "2.9 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_9 -bool false; else
		echo "* 2.9 Disable Power Nap" >> "$auditfilelocation"
		echo "$(date -u)" "2.9 fix" | tee -a "$logFile"
	fi
fi

# 3.1 Enable security auditing
# Verify organisational score
Audit3_1="$($Defaults read "$plistlocation" OrgScore3_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_1" = "1" ]; then
       auditdEnabled=$(launchctl list | grep -c auditd)
       if [ "$auditdEnabled" -gt "0" ]; then
           echo "$(date -u)" "3.1 passed" | tee -a "$logFile"
           $Defaults write "$plistlocation" OrgScore3_1 -bool false
       else
           echo "* 3.1 Enable security auditing" >> "$auditfilelocation"
           echo "$(date -u)" "3.1 fix" | tee -a "$logFile"
       fi
fi

# 3.2 Configure Security Auditing Flags
# Verify organisational score
Audit3_2="$($Defaults read "$plistlocation" OrgScore3_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit3_2" = "1" ]; then
	auditFlags="$(egrep "^flags:" /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ ${auditFlags} != *"ad"* ]];then
		echo "* 3.2 Configure Security Auditing Flags" >> "$auditfilelocation"
		echo "$(date -u)" "3.2 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "3.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_2 -bool false
	fi
fi

# 3.3 Retain install.log for 365 or more days 
# Verify organisational score
Audit3_3="$($Defaults read "$plistlocation" OrgScore3_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit3_3" = "1" ]; then
	installRetention="$(grep -i ttl /etc/asl/com.apple.install | awk -F'ttl=' '{print $2}')"
	# If client fails, then note category in audit file
	if [[ "$installRetention" = "" ]] || [[ "$installRetention" -lt "365" ]]; then
		echo "* 3.3 Retain install.log for 365 or more days" >> "$auditfilelocation"
		echo "$(date -u)" "3.3 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "3.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_3 -bool false
	fi
fi

# 3.4 Ensure security auditing retention
# Verify organisational score
Audit3_4="$($Defaults read "$plistlocation" OrgScore3_4)"
# If organisational score is 1 or true, check status of client
if [ "$Audit3_4" = "1" ]; then
	auditRetention="$(cat /etc/security/audit_control | egrep expire-after)"
	if [ "$auditRetention" = "expire-after:60d OR 1G" ]; then
		echo "$(date -u)" "3.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_4 -bool false; else
		echo "* 3.4 Ensure security auditing retention" >> "$auditfilelocation"
		echo "$(date -u)" "3.4 fix" | tee -a "$logFile"
		fi
	fi

# 3.5 Control access to audit records
# Audit only.  Remediation requires system inspection.
# Verify organisational score
Audit3_5="$($Defaults read "$plistlocation" OrgScore3_5)"
# If organisational score is 1 or true, check status of client
if [ "$Audit3_5" = "1" ]; then
	etccheck=$(ls -le /etc/security/audit_control | grep -v '\-r--------  1 root  wheel')
	varcheck=$(ls -le /var/audit | grep -v '\-r--r-----  1 root  wheel\|current\|total')
	if [[ "$etccheck" = "" ]] && [[ "$varcheck" = "" ]]; then
		echo "$(date -u)" "3.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_5 -bool false
	else
		echo "* 3.5 Control access to audit records" >> "$auditfilelocation"
		echo "$(date -u)" "3.5 fix" | tee -a "$logFile"
	fi
fi

# 3.6 Ensure Firewall is configured to log
# Verify organisational score
Audit3_6="$($Defaults read "$plistlocation" OrgScore3_6)"
# If organisational score is 1 or true, check status of client
if [ "$Audit3_6" = "1" ]; then
	FWlog=$(/usr/bin/profiles -P -o stdout | grep "EnableLogging" | awk '{print $3}' | cut -c 1)
	FwLogLevel=$(/usr/bin/profiles -P -o stdout | grep "LoggingOption" | awk '{print $3}')
	if [[ "$FWlog" = "1" ]]&&[[ $FwLogLevel == "detail;" ]]; then
		echo "$(date -u)" "3.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_6 -bool false; else
			echo "* 3.6 Ensure Firewall is configured to log custom Config profile, no remediation through Script" >> "$auditfilelocation"
			echo "$(date -u)" "3.6 fix check Custom CIS Config profile" | tee -a "$logFile"
		fi
fi

# 3.7 Audit Software Inventory
echo "$(date -u)" "3.7  Not Checked, Jamf provides inventory" | tee -a "$logFile"
echo "$(date -u)" "3.7 Jamf managed" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore3_7 -bool false

# 4.1 Disable Bonjour advertising service 
# Configuration Profile - Custom payload > com.apple.mDNSResponder > NoMulticastAdvertisements=true
# Configuration Profile - Custom Payload > com.apple.softwareUpdate > NoMulticastAdvertisements = 1
# Verify organisational score
Audit4_1="$($Defaults read "$plistlocation" OrgScore4_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit4_1" = "1" ]; then
    CP_bonjourAdvertise="$(/usr/bin/profiles -P -o stdout | grep "NoMulticastAdvertisements = 1;" | awk '{print $3}' | cut -c 1)"
	# If client fails, then note category in audit file
	if [[ "$CP_bonjourAdvertise" == "1" ]];then
		echo "$(date -u)" "4.1 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore4_1 -bool false
	else
		bonjourAdvertise="$( $Defaults read /Library/Preferences/com.apple.mDNSResponder | /usr/bin/grep NoMulticastAdvertisements )"
		if [ "$bonjourAdvertise" != "1" ] || [ "$boujourAdvertise" = "" ]; then
			echo "* 4.1 Disable Bonjour advertising service" >> "$auditfilelocation"
			echo "$(date -u)" "4.1 fix" | tee -a "$logFile"
		else
			echo "$(date -u)" "4.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore4_1 -bool false
		fi
	fi
fi

# 4.2 Enable "Show Wi-Fi status in menu bar" 
# Verify organisational score
Audit4_2="$($Defaults read "$plistlocation" OrgScore4_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit4_2" = "1" ]; then
	wifiMenuBar="$($Defaults -currentHost read com.apple.controlcenter.plist WiFi > /dev/null)"
	# If client fails, then note category in audit file
	if [[ "$wifiMenuBar" != "18" ]]; then
		echo "* 4.2 Enable Show Wi-Fi status in menu bar" >> "$auditfilelocation"
		echo "$(date -u)" "4.2 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "4.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore4_2 -bool false
	fi
fi

# 4.3 Audit Network Specific Locations
echo "$(date -u)" "4.3  Not Checked, Network Location could be corporate deployment" | tee -a "$logFile"
echo "$(date -u)" "4.3 passed" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore4_3 -bool false

# 4.4 Ensure http server is not running 
# Verify organisational score
Audit4_4="$($Defaults read "$plistlocation" OrgScore4_4)"
# If organisational score is 1 or true, check status of client
# Code fragment from https://github.com/krispayne/CIS-Settings/blob/master/ElCapitan_CIS.sh
if [ "$Audit4_4" = "1" ]; then
	httpdDisabled="$(launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => true')"
CountProcess="0"
for x in $(ps -ax | grep http | awk '{print $1 " " $4}' | grep http | awk '{print $1}' ); do
	CountProcess=$((CountProcess+1))
done
#echo "CountProcess is $CountProcess"
	if [ "$httpdDisabled" = 0 ] || [ "$CountProcess" > 0 ]; then
		echo "* 4.4 Ensure http server is not running" >> "$auditfilelocation"
		echo "$(date -u)" "4.4 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "4.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore4_4 -bool false
	fi
fi

# 4.5 Ensure nfs server is not running
# Verify organisational score
Audit4_5="$($Defaults read "$plistlocation" OrgScore4_5)"
# If organisational score is 1 or true, check status of client
if [ "$Audit4_5" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /etc/exports  ]; then
		echo "4.5 Ensure nfs server is not running" >> "$auditfilelocation"
		echo "$(date -u)" "4.5 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "4.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore4_5 -bool false
	fi
fi

# 4.6 Audit Wi-Fi Settings
echo "$(date -u)" "4.6  Not Checked, Security to request" | tee -a "$logFile"
echo "$(date -u)" "4.6 passed" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore4_6 -bool false

# 5.1.1 Secure Home Folders
# Verify organisational score
Audit5_1_1="$($Defaults read "$plistlocation" OrgScore5_1_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_1_1" = "1" ]; then
	homeFolders="$(find /Users -mindepth 1 -maxdepth 1 -type d -perm -1 | grep -v "Shared" | grep -v "Guest" | wc -l | xargs)"
	# If client fails, then note category in audit file
	if [ "$homeFolders" = "0" ]; then
		echo "$(date -u)" "5.1.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_1 -bool false; else
		echo "* 5.1.1 Secure Home Folders" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.1 fix" | tee -a "$logFile"
	fi
fi

# 5.1.2 Ensure System Integrity Protection Status (SIPS) Is Enabled
# Verify organisational score
Audit5_1_2="$($Defaults read "$plistlocation" OrgScore5_1_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_1_2" = "1" ]; then
	SIPStatus="$(/usr/bin/csrutil status | awk '{print $5}')"
	# If client fails, then note category in audit file
	if [ "$SIPStatus" = "enabled." ]; then
		echo "$(date -u)" "5.1.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_2 -bool false; else
		echo "* 5.1.2 System Integrity Protection Status (SIPS) Is Disabled" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.2 fix" | tee -a "$logFile"
	fi
fi

# 5.1.3 Ensure Apple Mobile File Integrity Is Enabled
# Verify organisational score
Audit5_1_3="$($Defaults read "$plistlocation" OrgScore5_1_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_1_3" = "1" ]; then
	amfIntegrity="$(/usr/sbin/nvram -p | /usr/bin/grep -c "amfi_get_out_of_my_way=1")"
	# If client fails, then note category in audit file
	if [ "$amfIntegrity" = "0" ]; then
		echo "$(date -u)" "5.1.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_3 -bool false; else
		echo "* 5.1.3 Apple Mobile File Integrity Is Disabled" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.3 fix" | tee -a "$logFile"
	fi
fi

# 5.1.4 Ensure Library Validation Is Enabled
# Verify organisational score
Audit5_1_4="$($Defaults read "$plistlocation" OrgScore5_1_4)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_1_4" = "1" ]; then
	# using an if statement to try and silence the error on this command
	if [[  -f "defaults read /Library/Preferences/com.apple.security.libraryvalidation.plist" ]];then
		libValidation="$(/usr/bin/defaults read /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation)"
	fi
	libValidationCP=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep DisableLibraryValidation | awk '{print $3}' | cut -c 1)
	# If client fails, then note category in audit file
	if [ "$libValidation" = "0" ]||[ "$libValidationCP" = "0" ]; then
		echo "$(date -u)" "5.1.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_4 -bool false; else
			echo "* 5.1.4 Check Ensure Library Validation Disabled" >> "$auditfilelocation"
			echo "$(date -u)" "5.1.4 fix" | tee -a "$logFile"
		fi
fi



# 5.1.5 Ensure Sealed System Volume (SSV) Is Enabled
# Verify organisational score
Audit5_1_5="$($Defaults read "$plistlocation" OrgScore5_1_5)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_1_5" = "1" ]; then
    ssvStatus="$(/usr/bin/csrutil authenticated-root status | awk '{print$4}')"
	# If client fails, then note category in audit file
	if [ "$ssvStatus" = "enabled" ]; then
		echo "$(date -u)" "5.1.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_5 -bool false; else
		echo "* 5.1.5 Sealed System Volume (SSV)" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.5 fix" | tee -a "$logFile"
	fi
fi

# 5.1.6 Check System Wide Applications for appropriate permissions
# Verify organisational score
Audit5_1_6="$($Defaults read "$plistlocation" OrgScore5_1_6)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_1_6" = "1" ]; then
	appPermissions="$(find /Applications -iname "*\.app" -type d -perm -2 -ls | wc -l | xargs)"
	# If client fails, then note category in audit file
	if [ "$appPermissions" = "0" ]; then
		echo "$(date -u)" "5.1.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_6 -bool false; else
		echo "* 5.1.6 Check System Wide Applications for appropriate permissions" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.6 fix" | tee -a "$logFile"
	fi
fi

# 5.1.7 Ensure No World Writable Files Exist in the System Folder
echo "$(date -u)" "5.1.7  Not checked, SIP Managed" | tee -a "$logFile"
echo "$(date -u)" "5.1.7 passed" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore5_1_7 -bool false

# 5.1.8 Check Library folder for world writable files
# Verify organisational score
Audit5_1_8="$($Defaults read "$plistlocation" OrgScore5_1_8)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_1_8" = "1" ]; then
	libPermissions="$(find /Library -type d -perm -2 -ls | grep -v Caches | grep -v Adobe | grep -v VMware | grep -v "/Audio/Data" | wc -l | xargs)"
#	# If client fails, then note category in audit file
	if [ "$libPermissions" = "0" ]; then
		echo "$(date -u)" "5.1.8 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_8 -bool false; else
		echo "* 5.1.8 Check Library folder for world writable files" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.8 fix" | tee -a "$logFile"
	fi
fi


# 5.10 Require an administrator password to access system-wide preferences
# Verify organisational score
Audit5_10="$($Defaults read "$plistlocation" OrgScore5_10)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_10" = "1" ]; then
	adminSysPrefs="$(security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep -E '(true|false)' | grep -c "true")"
	# If client fails, then note category in audit file
	if [ "$adminSysPrefs" = "1" ]; then
		echo "* 5.10 Require an administrator password to access system-wide preferences" >> "$auditfilelocation"
		echo "$(date -u)" "5.10 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "5.10 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_10 -bool false
	fi
fi

# 5.11 Disable ability to login to another user's active and locked session
# Verify organisational score
Audit5_11="$($Defaults read "$plistlocation" OrgScore5_11)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_11" = "1" ]; then
	screensaverRules="$(/usr/bin/security authorizationdb read system.login.screensaver 2>&1 | grep -c 'use-login-window-ui')"
	# If client fails, then note category in audit file
	if [ "$screensaverRules" = "1" ]; then
		echo "$(date -u)" "5.11 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_11 -bool false
     else
		echo "* 5.11 Disable ability to login to another users active and locked session" >> "$auditfilelocation"
		echo "$(date -u)" "5.11 fix" | tee -a "$logFile"
	fi
fi

# 5.12 Create a custom message for the Login Screen
# Configuration Profile - LoginWindow payload > Window > Banner (message)
# Verify organisational score
Audit5_12="$($Defaults read "$plistlocation" OrgScore5_12)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_12" = "1" ]; then
	CP_loginMessage="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'LoginwindowText')"
	# If client fails, then note category in audit file
	if [[ "$CP_loginMessage" -gt "0" ]] ; then
		echo "$(date -u)" "5.12 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_12 -bool false; else
		loginMessage="$($Defaults read /Library/Preferences/com.apple.loginwindow.plist LoginwindowText)"
		if [[ $loginMessage = "" ]] || [[ $loginMessage = *"does not exist"* ]]; then
			echo "* 5.12 Create a custom message for the Login Screen" >> "$auditfilelocation"
			echo "$(date -u)" "5.12 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "5.12 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_12 -bool false
		fi
	fi
fi

# 5.13 Create a Login window banner
# Policy Banner https://support.apple.com/en-us/HT202277
# Verify organisational score
Audit5_13="$($Defaults read "$plistlocation" OrgScore5_13)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_13" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /Library/Security/PolicyBanner.txt ] || [ -e /Library/Security/PolicyBanner.rtf ] || [ -e /Library/Security/PolicyBanner.rtfd ]; then
		echo "$(date -u)" "5.13 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_13 -bool false; else
		echo "* 5.13 Create a Login window banner" >> "$auditfilelocation"
		echo "$(date -u)" "5.13 fix" | tee -a "$logFile"
	fi
fi

# 5.14 Disable "Show password hints"
# Configuration Profile - LoginWindow payload > Options > Show password hint when needed and available (unchecked - Yes this is backwards)
# Verify organisational score
Audit5_14="$($Defaults read "$plistlocation" OrgScore5_14)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_14" = "1" ]; then
	CP_passwordHints="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'RetriesUntilHint = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_passwordHints" -gt "0" ]] ; then
		echo "$(date -u)" "5.14 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_14 -bool false; else
		passwordHints="$($Defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint)"
		if [ "$passwordHints" -gt 0 ] || [ "$passwordHints" = *exist* ]; then
			echo "* 5.14 Disable Show password hints" >> "$auditfilelocation"
			echo "$(date -u)" "5.14 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "5.14 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_14 -bool false
		fi
	fi
fi

# 5.15 Ensure Fast User Switching Is Disabled
# Verify organisational score
Audit5_15="$($Defaults read "$plistlocation" OrgScore5_15)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_15" = "1" ]; then
	FastUserSwitching=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "MultipleSessionEnabled" | awk 'NR==1 {print $3+0}')
		# If client fails, then note category in audit file
		if [ "$FastUserSwitching" == 0 ]; then
			echo "$(date -u)" "5.15 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_15 -bool false
		else
				echo "* 5.15 Check Restrictions Profile for Fast User Switching Settings " >> "$auditfilelocation"
				echo "$(date -u)" "5.15 check Restrictions Profile" | tee -a "$logFile"
		fi
fi

# 5.2.1 Ensure Password Account Lockout Threshold Is Configured
# Config profile managed
#
# Verify organisational score
Audit5_2_1="$($Defaults read "$plistlocation" OrgScore5_2_1)"
# If organisational score is 1 or true, check status of client

if [ "$Audit5_2_1" = "1" ]; then
	maxFailedPW=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "maxFailedAttempts" | awk '{print $3}' | cut -c 1)	# If client fails, then note category in audit file
	if [[ ${maxFailedPW} -le 5 ]];then
		echo "$(date -u)" "5.2.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_2_1 -bool false
	else
		echo "* 5.2.1 CheckPassword History" >> "$auditfilelocation"
		echo "$(date -u)" "5.2.1 fix" | tee -a "$logFile"
	fi
fi

# 5.2.2 Ensure Password Minimum Length Is Configured
# Config profile managed
#
# Verify organisational score
Audit5_2_2="$($Defaults read "$plistlocation" OrgScore5_2_2)"
# If organisational score is 1 or true, check status of client

if [ "$Audit5_2_2" = "1" ]; then
	pwLength=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "minlength" | awk '{print $3}' | cut -c 1)	
	# If client fails, then note category in audit file
	if [[ ${pwLength} -le 8 ]];then
		echo "$(date -u)" "5.2.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_2_2 -bool false
	else
		echo "* 5.2.2 Check Password Length in Config profile." >> "$auditfilelocation"
		echo "$(date -u)" "5.2.2 fix" | tee -a "$logFile"
	fi
fi

# 5.2.3 Ensure Complex Password Must Contain Alphabetic Characters Is Configured
# Config profile managed
#
# Verify organisational score
Audit5_2_3="$($Defaults read "$plistlocation" OrgScore5_2_3)"
# If organisational score is 1 or true, check status of client

if [ "$Audit5_2_3" = "1" ]; then
	pwAlpha=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "requireAlphanumeric" | awk '{print $3}' | cut -c 1)	
# If client fails, then note category in audit file
	if [[ ${pwAlpha} -ge 1 ]];then
		echo "$(date -u)" "5.2.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_2_3 -bool false
	else
		echo "* 5.2.3 Check Password complexity in Config Profile" >> "$auditfilelocation"
		echo "$(date -u)" "5.2.3 fix" | tee -a "$logFile"
	fi
fi


# 5.2.4 Ensure Complex Password Must Contain Numeric Character Is Configured
# Config profile managed
#
# Verify organisational score
Audit5_2_4="$($Defaults read "$plistlocation" OrgScore5_2_4)"
# If organisational score is 1 or true, check status of client

if [ "$Audit5_2_4" = "1" ]; then
	pwAlpha=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "requireAlphanumeric" | awk '{print $3}' | cut -c 1)	# If client fails, then note category in audit file
	if [[ ${pwAlpha} -ge 1 ]];then
		echo "$(date -u)" "5.2.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_2_4 -bool false
	else
		echo "* 5.2.4 Check Password complexity in Config Profile" >> "$auditfilelocation"
		echo "$(date -u)" "5.2.4 fix" | tee -a "$logFile"
	fi
fi


# 5.2.5 Ensure Complex Password Must Contain Special Character Is Configured
# Config profile managed
#
# Verify organisational score
Audit5_2_5="$($Defaults read "$plistlocation" OrgScore5_2_5)"
# If organisational score is 1 or true, check status of client

if [ "$Audit5_2_5" = "1" ]; then
	pwComplexChar=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "minComplexChars" | awk '{print $3}' | cut -c 1)	# If client fails, then note category in audit file
	if [[ ${pwComplexChar} -ge 1 ]];then
		echo "$(date -u)" "5.2.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_2_5 -bool false
	else
		echo "* 5.2.5 Check Password complexity in Config Profile" >> "$auditfilelocation"
		echo "$(date -u)" "5.2.5 fix" | tee -a "$logFile"
	fi
fi

# 5.2.6 Ensure Complex Password Must Contain Uppercase and Lowercase Characters Is Configured
# Config profile managed
#
# Verify organisational score
Audit5_2_6="$($Defaults read "$plistlocation" OrgScore5_2_6)"
# If organisational score is 1 or true, check status of client

if [ "$Audit5_2_6" = "1" ]; then
	pwUpperLower=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "minComplexChars" | awk '{print $3}' | cut -c 1)	# If client fails, then note category in audit file
	if [[ ${pwUpperLower} -ge 1 ]];then
		echo "$(date -u)" "5.2.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_2_6 -bool false
	else
		echo "* 5.2.6 Check Password complexity in Config Profile" >> "$auditfilelocation"
		echo "$(date -u)" "5.2.6 fix" | tee -a "$logFile"
	fi
fi

# 5.2.7 Ensure Password Age Is Configured
# Config profile managed
#
# Verify organisational score
Audit5_2_7="$($Defaults read "$plistlocation" OrgScore5_2_7)"
# If organisational score is 1 or true, check status of client

if [ "$Audit5_2_7" = "1" ]; then
	pwHistory=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "pinHistory" | awk '{print $3}' | cut -c 1)	# If client fails, then note category in audit file
	if [[ ${pwHistory} -ge 1 ]];then
		echo "$(date -u)" "5.2.7 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_2_7 -bool false
	else
		echo "* 5.2.7 Check Password History in Config Profile" >> "$auditfilelocation"
		echo "$(date -u)" "5.2.7 fix" | tee -a "$logFile"
	fi
fi

# 5.2.8 Ensure Password History Is Configured
# Config profile managed
#
# Verify organisational score
Audit5_2_8="$($Defaults read "$plistlocation" OrgScore5_2_8)"
# If organisational score is 1 or true, check status of client

if [ "$Audit5_2_8" = "1" ]; then
pwHistoryCheck=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep "pinHistory" | awk 'NR==1 {print$3+0}')
# If client fails, then note category in audit file
if [[ ${pwHistoryCheck} -ge 5 ]];then
echo "$(date -u)" "5.2.8 passed CIS Suggests 15 Previous not 5" | tee -a "$logFile"
$Defaults write "$plistlocation" OrgScore5_2_8 -bool false
else
echo "* 5.2.8 Check Password History in Config Profile" >> "$auditfilelocation"
echo "$(date -u)" "5.2.8 fix" | tee -a "$logFile"
fi
fi

# 5.3 Reduce the sudo timeout period
# Verify organisational score
Audit5_3="$($Defaults read "$plistlocation" OrgScore5_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_3" = "1" ]; then
    sudoTimeout="$(cat /private/etc/sudoers.d/defaults_timestamp_timeout | grep -c 'timestamp_timeout = 0')"
	# If client fails, then note category in audit file
	if [ "$sudoTimeout" = "" ]; then
		echo "* 5.3 Reduce the sudo timeout period" >> "$auditfilelocation"
		echo "$(date -u)" "5.3 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "5.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_3 -bool false
	fi
fi

# 5.4 Use a separate timestamp for each user/tty combo
# Verify organisational score
Audit5_4="$($Defaults read "$plistlocation" OrgScore5_4)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_4" = "1" ]; then
	ttyTimestamp="$(cat /etc/sudoers | egrep tty_tickets)"
	# If client fails, then note category in audit file
	if [ "$ttyTimestamp" != "" ]; then
		echo "* 5.4 Use a separate timestamp for each user/tty combo" >> "$auditfilelocation"
		echo "$(date -u)" "5.4 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "5.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_4 -bool false
	fi
fi

# 5.5 Ensure login keychain is locked when the computer sleeps
# Verify organisational score
Audit5_5="$($Defaults read "$plistlocation" OrgScore5_5)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_5" = "1" ]; then
	lockSleep="$(security show-keychain-info /Users/"$currentUser"/Library/Keychains/login.keychain 2>&1 | grep -c "lock-on-sleep")"
	# If client fails, then note category in audit file
	if [ "$lockSleep" = 0 ]; then
		echo "* 5.5 Ensure login keychain is locked when the computer sleeps" >> "$auditfilelocation"
		echo "$(date -u)" "5.5 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "5.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_5 -bool false
	fi
fi

# 5.6 Do not enable the "root" account
# Verify organisational score
Audit5_6="$($Defaults read "$plistlocation" OrgScore5_6)"
if [ "$Audit5_6" = "1" ]; then
	#echo "$(date -u)" "Checking 5.6" | tee -a "$logFile"
	rootEnabled="$(dscl . -read /Users/root AuthenticationAuthority 2>&1 | grep -c "No such key")"
	rootEnabledRemediate="$(dscl . -read /Users/root UserShell 2>&1 | grep -c "/usr/bin/false")"
	if [ "$rootEnabled" = "1" ]; then
		echo "$(date -u)" "5.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_6 -bool false; elif
		[ "$rootEnabledRemediate" = "1" ]; then
		   echo "$(date -u)" "5.6 passed due to remediation" | tee -a "$logFile"
		   $Defaults write "$plistlocation" OrgScore5_6 -bool false
	else
	echo "* 5.6 Do Not enable the "root" account" >> "$auditfilelocation"
	echo "$(date -u)" "5.6 fix" | tee -a "$logFile"

	fi
fi

# 5.7 Disable automatic login
# Configuration Profile - LoginWindow payload > Options > Disable automatic login (checked)
# Verify organisational score
Audit5_7="$($Defaults read "$plistlocation" OrgScore5_7)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_7" = "1" ]; then
	CP_autologinEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableAutoLoginClient')"
	# If client fails, then note category in audit file
	if [[ "$CP_autologinEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "5.7 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_7 -bool false; else
		autologinEnabled="$($Defaults read /Library/Preferences/com.apple.loginwindow | grep -ow "autoLoginUser")"
		if [ "$autologinEnabled" = "" ]; then
			echo "$(date -u)" "5.7 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_7 -bool false; else
			echo "* 5.7 Disable automatic login" >> "$auditfilelocation"
			echo "$(date -u)" "5.7 fix" | tee -a "$logFile"
		fi
	fi
fi

# 5.8 Require a password to wake the computer from sleep or screen saver
# Configuration Profile - Security and Privacy payload > General > Require password * after sleep or screen saver begins (checked)
# Verify organisational score
Audit5_8="$($Defaults read "$plistlocation" OrgScore5_8)"
# If organisational score is 1 or true, check status of client
# If client fails, then note category in audit file
if [ "$Audit5_8" = "1" ]; then
	CP_screensaverPwd="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'askForPassword = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_screensaverPwd" -gt "0" ]] ; then
		echo "$(date -u)" "5.8 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_8 -bool false; else
		screensaverPwd="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.screensaver askForPassword)"
		if [ "$screensaverPwd" = "1" ]; then
			echo "$(date -u)" "5.8 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_8 -bool false; else
			echo "* 5.8 Require a password to wake the computer from sleep or screen saver" >> "$auditfilelocation"
			echo "$(date -u)" "5.8 fix" | tee -a "$logFile"
		fi
	fi
fi

# 5.9 Ensure system is set to hibernate 
# %Comment%
Audit5_9="$($Defaults read "$plistlocation" OrgScore5_9)"
# If organisational score is 1 or true, check status of client
# Code fragment from https://github.com/krispayne/CIS-Settings/blob/master/ElCapitan_CIS.sh
if [ "$Audit5_9" = "1" ]; then
	# Check if MacBook
	macType=$(system_profiler SPHardwareDataType | egrep -e "Model Name:" | awk '{print $3}')
	standByDeplayLow=$(pmset -g | grep -e standbydelaylow | awk '{print $2}')
	standByDelayHigh=$(pmset -g | grep -e standbydelayhigh | awk '{print $2}')
	highStandByThreshold=$(pmset -g | grep -e highstandbythreshold | awk '{print $2}')
	DestroyFVKeyOnStandby=$(pmset -g | grep -e DestroyFVKeyOnStandby | awk '{print $2}')
	HibernateMode=$(pmset -g | grep -e hibernatemode | awk '{print $2}')
	if [[ "$macType" == "MacBook" ]];then
		if [[ "$HibernateMode" == "25" ]]&&[[  "$highStandByThreshold" -ge "90" ]]&&[[  "$standByDelayHigh" -le "600" ]]&&[[  "$highStandByThreshold" -le "600" ]]&&[[ "$DestroyFVKeyOnStandby" == "1" ]]; then
			echo "$(date -u)" "5.9 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_9 -bool false
		else
			echo "* 5.9 Ensure system is set to hibernate " >> "$auditfilelocation"
			echo "$(date -u)" "5.9 fix" | tee -a "$logFile"
		fi
	else
		echo "$(date -u)" "5.9 passed - Hardware mismatch" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_9 -bool false
	fi
fi

# 6.1.1 Display login window as name and password
# Configuration Profile - LoginWindow payload > Window > LOGIN PROMPT > Name and password text fields (selected)
# Verify organisational score
Audit6_1_1="$($Defaults read "$plistlocation" OrgScore6_1_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_1_1" = "1" ]; then
	CP_loginwindowFullName="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SHOWFULLNAME = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_loginwindowFullName" -gt "0" ]] ; then
		echo "$(date -u)" "6.1.1 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_1 -bool false; else
		loginwindowFullName="$($Defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME)"
		if [ "$loginwindowFullName" != "1" ]; then
			echo "* 6.1.1 Display login window as name and password" >> "$auditfilelocation"
			echo "$(date -u)" "6.1.1 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "6.1.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore6_1_1 -bool false
		fi
	fi
fi

# 6.1.2 Ensure Show Password Hints Is Disabled
# Adjusted due to error in original file
# Verify organisational score
Audit6_1_2="$($Defaults read "$plistlocation" OrgScore6_1_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_1_2" = "1" ]; then
	passwordHint=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep 'RetriesUntilHint' | awk 'NR==1 {print $3+0}')
	# If client fails, then note category in audit file
	if [ "$passwordHint" == 0 ]; then
		echo "$(date -u)" "6.1.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_2 -bool false
	else
			echo "* 6.1.2 Ensure Show Password Hints Is Disabled" >> "$auditfilelocation"
			echo "$(date -u)" "6.1.2 fix" | tee -a "$logFile"
		fi
fi

# 6.1.3 Ensure Guest Account Is Disabled
# Adjusted due to error in original file
# Verify organisational score
Audit6_1_3="$($Defaults read "$plistlocation" OrgScore6_1_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_1_3" = "1" ]; then
	disableGuest=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep 'DisableGuestAccount' | awk 'NR==1 {print $3+0}')
	allowEnableGuest=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep 'EnableGuestAccount' | awk 'NR==1 {print $3+0}')
	# If client fails, then note category in audit file
	if [ "$disableGuest" == 1 ] && [ "$allowEnableGuest" == 0 ]; then
		echo "$(date -u)" "6.1.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_3 -bool false
	else
		echo "* 6.1.3 Ensure Guest Account Is Disabled" >> "$auditfilelocation"
		echo "$(date -u)" "6.1.3 fix" | tee -a "$logFile"
	fi
fi

# 6.1.4 Disable "Allow guests to connect to shared folders"
# Configuration Profile - 6.1.4 Disable Allow guests to connect to shared folders - Custom payload > com.apple.AppleFileServer guestAccess=false, com.apple.smb.server AllowGuestAccess=false
# Verify organisational score
Audit6_1_4="$($Defaults read "$plistlocation" OrgScore6_1_4)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_1_4" = "1" ]; then
	CP_afpGuestEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'guestAccess = 0')"
	CP_smbGuestEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AllowGuestAccess = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_afpGuestEnabled" -gt "0" ]] || [[ "$CP_smbGuestEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "6.1.4 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_4 -bool false; else
		afpGuestEnabled="$($Defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess)"
		smbGuestEnabled="$($Defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess)"
		if [ "$afpGuestEnabled" = "1" ] || [ "$smbGuestEnabled" = "1" ]; then
			echo "* 6.1.4 Disable Allow guests to connect to shared folders" >> "$auditfilelocation"
			echo "$(date -u)" "6.1.4 fix" | tee -a "$logFile"
		else
			echo "$(date -u)" "6.1.4 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore6_1_4 -bool false
		fi
	fi
fi

# 6.1.5 Remove Guest home folder
# Verify organisational score
Audit6_1_5="$($Defaults read "$plistlocation" OrgScore6_1_5)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_1_5" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /Users/Guest ]; then
		echo "* 6.1.5 Remove Guest home folder" >> "$auditfilelocation"
		echo "$(date -u)" "6.1.5 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "6.1.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_5 -bool false
	fi
fi

# 6.2 Turn on filename extensions
# Does not work as a Configuration Profile - .GlobalPreferences.plist
# Verify organisational score
Audit6_2="$($Defaults read "$plistlocation" OrgScore6_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_2" = "1" ]; then
		filenameExt="$($Defaults read /Users/"$currentUser"/Library/Preferences/.GlobalPreferences.plist AppleShowAllExtensions)"
	# If client fails, then note category in audit file
	if [ "$filenameExt" = "1" ]; then
		echo "$(date -u)" "6.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_2 -bool false; else
		echo "* 6.2 Turn on filename extensions" >> "$auditfilelocation"
		echo "$(date -u)" "6.2 fix" | tee -a "$logFile"
	fi
fi

# 6.3 Disable the automatic run of safe files in Safari
# Configuration Profile - Custom payload > com.apple.Safari > AutoOpenSafeDownloads=false
# Verify organisational score
Audit6_3="$($Defaults read "$plistlocation" OrgScore6_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_3" = "1" ]; then
	CP_safariSafe="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AutoOpenSafeDownloads = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_safariSafe" -gt "0" ]] ; then
		echo "$(date -u)" "6.3 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_3 -bool false; else
		safariSafe="$(/usr/libexec/PlistBuddy -c "Print:AutoOpenSafeDownloads" /Users/"$currentUser"/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist)"
		if [[ "$safariSafe" = "true" ]]; then
			echo "* 6.3 Disable the automatic run of safe files in Safari" >> "$auditfilelocation"
			echo "$(date -u)" "6.3 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "6.3 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore6_3 -bool false
		fi
	fi
fi

echo "$(date -u)" "Audit complete" | tee -a "$logFile"

exit 0

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
# github.com/jamfprofessionalservices
# updated for 10.13 CIS benchmarks by Erin McDonald, Jamf Jan 2019
# updated for 10.15 CIS benchmarks by Erin McDonald, Jamf 2020
# updated for macOS12 CIS benchmarks by Tomos Tyler, D8 Services 2022

# USAGE
# Reads from plist at /Library/Application Support/SecurityScoring/org_security_score.plist by default.
# For "true" items, runs query for current computer/user compliance.
# Non-compliant items are logged to /Library/Application Support/SecurityScoring/org_audit

plistlocation="/Library/Application Support/SecurityScoring/org_security_score.plist"
configProfileCISPrefs="/Library/Managed Preferences/com.d8services.cispreferences.plist"

currentUser="$(/usr/bin/stat -f%Su /dev/console)"
currentUserID="$(/usr/bin/id -u $currentUser)"
hardwareUUID="$(/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | awk -F ": " '{print $2}' | xargs)"

logFile="/Library/Application Support/SecurityScoring/remediation.log"
# Append to existing logFile
echo "$(date -u)" "Beginning remediation" >> "$logFile"
# Create new logFile
# echo "$(date -u)" "Beginning remediation" > "$logFile"	

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


# 1.1 Verify all Apple provided software is current
# Verify organizational score
Audit1_1="$(defaults read "$plistlocation" OrgScore1_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_1" = "1" ]; then
	echo "$(date -u)" "1.1 remediated" | tee -a "$logFile"
	# NOTE: INSTALLS ALL RECOMMENDED SOFTWARE UPDATES FROM CLIENT'S CONFIGURED SUS SERVER
	softwareupdate -i -r
fi

# 1.2 Enable Auto Update
# Verify organisational score
Audit1_2="$(defaults read "$plistlocation" OrgScore1_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_2" = "1" ]; then
	defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -int 1
	echo "$(date -u)" "1.2 remediated" | tee -a "$logFile"
fi

# 1.3 Enable Download new updates when available
# Verify organisational score
Audit1_3="$(defaults read "$plistlocation" OrgScore1_3)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_3" = "1" ]; then
	defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -int 1
	echo "$(date -u)" "1.3 remediated" | tee -a "$logFile"
fi

# 1.4 Enable app update installs
# Verify organisational score
Audit1_4="$(defaults read "$plistlocation" OrgScore1_4)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_4" = "1" ]; then
	defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true
	echo "$(date -u)" "1.4 remediated" | tee -a "$logFile"
fi

# 1.5 Enable system data files and security update installs 
# Verify organisational score
Audit1_5="$(defaults read "$plistlocation" OrgScore1_5)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_5" = "1" ]; then
	defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true
	defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
	echo "$(date -u)" "1.5 remediated" | tee -a "$logFile"
fi

# 1.6 Enable macOS update installs 
# Verify organisational score
Audit1_6="$(defaults read "$plistlocation" OrgScore1_6)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_6" = "1" ]; then
	defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true
	echo "$(date -u)" "1.6 remediated" | tee -a "$logFile"
fi

# 1.7 Audit Computer Name  
# Verify organisational score
Audit1_7="$(defaults read "$plistlocation" OrgScore1_7)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit1_7" = "1" ]; then
	serialN=$(system_profiler SPHardwareDataType | awk '/Serial Number/{print $4}')
	/usr/sbin/scutil --set ComputerName "${serialN}"
	/usr/sbin/scutil --set LocalHostName "${serialN}"
	/usr/sbin/scutil --set HostName "${serialN}"
	dscacheutil -flushcache
	echo "$(date -u)" "1.7 remediated" | tee -a "$logFile"
fi

# 2.1.1 Turn off Bluetooth, if no paired devices exist
# Verify organisational score
Audit2_1_1="$(defaults read "$plistlocation" OrgScore2_1_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_1_1" = "1" ]; then
	echo "$(date -u)" "Checking 2.1.1" | tee -a "$logFile"
	connectable="$( system_profiler SPBluetoothDataType | grep -c "Paired: Yes" )"
	if [ "$connectable" -gt 0 ]; then
		echo "$(date -u)" "2.1.1 passed" | tee -a "$logFile"
	else
		defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -bool false
		killall -HUP bluetoothd
		echo "$(date -u)" "2.1.1 remediated" | tee -a "$logFile"
	fi
fi

# 2.1.2 Show Bluetooth status in menu bar
# Verify organisational score
Audit2_1_2="$(defaults read "$plistlocation" OrgScore2_1_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_1_2" = "1" ]; then
	open "/System/Library/CoreServices/Menu Extras/Bluetooth.menu"
	echo "$(date -u)" "2.1.2 remediated" | tee -a "$logFile"
fi


# 2.10 Enable Secure Keyboard Entry in terminal.app 
# Verify organisational score
Audit2_10="$(defaults read "$plistlocation" OrgScore2_10)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_10" = "1" ]; then
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.Terminal SecureKeyboardEntry -bool true
	iTerm="$(defaults read -app iTerm | /usr/bin/grep -c "Couldn't find an application")"
	if [ "$iTerm" -gt "0" ]; then
		defaults write -app iTerm "Secure Input" -bool true
	fi
	echo "$(date -u)" "2.10 remediated" | tee -a "$logFile"
fi


# 2.14 Audit Sidecar Settings
echo "$(date -u)" "2.14  Not remediated, Check Custom CIS Profile" | tee -a "$logFile"

# 2.15 Audit Touch ID and Wallet & Apple Pay Settings
# Manual Intervention only

# 2.16 Audit Notification System Preference Settings
#echo "$(date -u)" "2.16  Not remediated, Manual Intervention required" | tee -a "$logFile"

# 2.17 Audit Passwords System Preference Setting
echo "$(date -u)" "2.17  Not remediated, Password Policy in effect" | tee -a "$logFile"

## 2.2.1 Enable "Set time and date automatically" (Not Scored)
# Verify organisational score
Audit2_2_1="$(defaults read "$plistlocation" OrgScore2_2_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_2_1" = "1" ]; then
	systemsetup -setusingnetworktime on
	echo "$(date -u)" "2.2.1 remediated" | tee -a "$logFile"
fi

# 2.2.2 Ensure time set is within appropriate limits
# Not audited - only enforced if identified as priority
# Verify organisational score
Audit2_2_2="$(defaults read "$plistlocation" OrgScore2_2_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_2_2" = "1" ]; then
	systemsetup -setusingnetworktime off 2>&1
	systemsetup -setusingnetworktime on 2>&1
#	timeServer="$(systemsetup -getnetworktimeserver | awk '{print $4}')"
#	ntpdate -sv "$timeServer"
	echo "$(date -u)" "2.2.2 enforced" | tee -a "$logFile"
fi

# 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver 
# Verify organisational score
Audit2_3_1="$(defaults read "$plistlocation" OrgScore2_3_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_3_1" = "1" ]; then
	defaults write /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.screensaver."$hardwareUUID".plist idleTime -int 1200
	echo "$(date -u)" "2.3.1 remediated" | tee -a "$logFile"
fi

# 2.3.2 Secure screen saver corners 
# Verify organisational score
Audit2_3_2="$(defaults read "$plistlocation" OrgScore2_3_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_3_2" = "1" ]; then
	killDock=false
	bl_corner="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)"
	tl_corner="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)"
	tr_corner="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)"
	br_corner="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)"
	if [ "$bl_corner" = "6" ]; then
		echo "Disabling bottom left hot corner"
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner -int 1
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-modifier -int 0
		killDock=true
	fi
	if [ "$tl_corner" = "6" ]; then
		echo "Disabling top left hot corner"
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner -int 1
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-modifier -int 0
		killDock=true
	fi
	if [ "$tr_corner" = "6" ]; then
		echo "Disabling top right hot corner"
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner -int 1
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-modifier -int 0
		killDock=true
	fi
	if [ "$br_corner" = "6" ]; then
		echo "Disabling bottom right hot corner"
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner -int 1
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-modifier -int 0
		killDock=true
	fi
	## ensure proper ownership of plist
	/usr/sbin/chown "$currentUser" /Users/"$currentUser"/Library/Preferences/com.apple.dock.plist

	if $killDock;then
		/usr/bin/killall Dock
		echo "$(date -u)" "2.3.2 remediated" | tee -a "$logFile"
	fi
fi


# 2.3.3 Familiarize users with screen lock tools or corner to Start Screen Saver  
# Verify organisational score
Audit2_3_3="$(defaults read "$plistlocation" OrgScore2_3_3)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
# Sets bottom left corner to start screen saver
if [ "$Audit2_3_3" = "1" ]; then
	bl_corner="$(defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)"
	if [ "$bl_corner" != "5" ]; then
		echo "Setting bottom left to start screen saver" | tee -a "$logFile"
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner -int 5
		/usr/bin/defaults write /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-modifier -int 0
		## ensure proper ownership of plist
		/usr/sbin/chown "$currentUser" /Users/"$currentUser"/Library/Preferences/com.apple.dock.plist
		/usr/bin/killall Dock
		echo "$(date -u)" "2.3.3 remediated" | tee -a "$logFile"
	fi
fi

# 2.4.1 Disable Remote Apple Events 
# Requires Full Disk Access privileges	
# Verify organisational score
Audit2_4_1="$(defaults read "$plistlocation" OrgScore2_4_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_1" = "1" ]; then
		/usr/sbin/systemsetup -setremoteappleevents off
		echo "$(date -u)" "2.4.1 remediated" | tee -a "$logFile"
fi


# 2.4.10 Disable Internet Sharing 
# Verify organisational score
Audit2_4_10="$(defaults read "$plistlocation" OrgScore2_4_10)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_10" = "1" ]; then
	/usr/libexec/PlistBuddy -c "Delete :NAT:AirPort:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Add :NAT:AirPort:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Delete :NAT:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Add :NAT:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Delete :NAT:PrimaryInterface:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Add :NAT:PrimaryInterface:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	
	## breaks internet connection sharing
	cat > /Library/LaunchDaemons/sysctl.plist << EOF
<?xml version="2.4.10" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 2.4.10//EN" "http://www.apple.com/DTDs/PropertyList-2.4.10.dtd">
<plist version="2.4.10">
	<dict>
		<key>Label</key>
		<string>sysctl</string>
		<key>ProgramArguments</key>
		<array>
			<string>/usr/sbin/sysctl</string>
			<string>net.inet.ip.forwarding=0</string>
		</array>
		<key>WatchPaths</key>
		<array>
			<string>/Library/Preferences/SystemConfiguration</string>
		</array>
		<key>RunAtLoad</key>
		<true/>
	</dict>
</plist>
EOF
	if [ $(/bin/launchctl list | grep sysctl | awk '{ print $NF }') = "sysctl" ];then
		/bin/launchctl unload /Library/LaunchDaemons/sysctl.plist
	fi
	/bin/launchctl load /Library/LaunchDaemons/sysctl.plist
    
	echo "$(date -u)" "2.4.10 enforced" | tee -a "$logFile"
fi

# 2.4.12 Ensure Media Sharing Is Disabled
echo "$(date -u)" "2.4.12  Not remediated, Check CIS Custom Profile" | tee -a "$logFile"

# 2.4.2 Disable Internet Sharing 
# Verify organisational score
Audit2_4_2="$(defaults read "$plistlocation" OrgScore2_4_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_2" = "1" ]; then
	/usr/libexec/PlistBuddy -c "Delete :NAT:AirPort:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Add :NAT:AirPort:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Delete :NAT:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Add :NAT:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Delete :NAT:PrimaryInterface:Enabled"  /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	/usr/libexec/PlistBuddy -c "Add :NAT:PrimaryInterface:Enabled bool false" /Library/Preferences/SystemConfiguration/com.apple.nat.plist
	
	## breaks internet connection sharing
	cat > /Library/LaunchDaemons/sysctl.plist << EOF
<?xml version="2.4.2" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 2.4.2//EN" "http://www.apple.com/DTDs/PropertyList-2.4.2.dtd">
<plist version="2.4.2">
	<dict>
		<key>Label</key>
		<string>sysctl</string>
		<key>ProgramArguments</key>
		<array>
			<string>/usr/sbin/sysctl</string>
			<string>net.inet.ip.forwarding=0</string>
		</array>
		<key>WatchPaths</key>
		<array>
			<string>/Library/Preferences/SystemConfiguration</string>
		</array>
		<key>RunAtLoad</key>
		<true/>
	</dict>
</plist>
EOF
	if [ $(/bin/launchctl list | grep sysctl | awk '{ print $NF }') = "sysctl" ];then
		/bin/launchctl unload /Library/LaunchDaemons/sysctl.plist
	fi
	/bin/launchctl load /Library/LaunchDaemons/sysctl.plist
    
	echo "$(date -u)" "2.4.2 enforced" | tee -a "$logFile"
fi


# 2.4.3 Disable Screen Sharing 
# Verify organisational score
Audit2_4_3="$(defaults read "$plistlocation" OrgScore2_4_3)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_3" = "1" ]; then
	/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist
	/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
	echo "$(date -u)" "2.4.3 remediated" | tee -a "$logFile"
fi

# 2.4.4 Disable Printer Sharing 
# Verify organisational score
Audit2_4_4="$(defaults read "$plistlocation" OrgScore2_4_4)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_4" = "1" ]; then
	/usr/sbin/cupsctl --no-share-printers
	while read -r _ _ printer _; do
		/usr/sbin/lpadmin -p "${printer/:}" -o printer-is-shared=false
	done < <(/usr/bin/lpstat -v)
	echo "$(date -u)" "2.4.4 remediated" | tee -a "$logFile"
fi


# 2.4.5 Disable Remote Login 
# Requires full disk access
# Verify organisational score
Audit2_4_5="$(defaults read "$plistlocation" OrgScore2_4_5)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_5" = "1" ]; then
	/usr/sbin/systemsetup -f -setremotelogin off
	echo "$(date -u)" "2.4.5 remediated" | tee -a "$logFile"
fi

# 2.4.6 Disable DVD or CD Sharing 
# Verify organisational score
Audit2_4_6="$(defaults read "$plistlocation" OrgScore2_4_6)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_6" = "1" ]; then
	/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.ODSAgent.plist
#ERROR HERE
	echo "$(date -u)" "2.4.6 remediated" | tee -a "$logFile"
fi

# 2.4.7 Disable Bluetooth Sharing
# Verify organisational score
Audit2_4_7="$(defaults read "$plistlocation" OrgScore2_4_7)"
# If organisational score is 1 or true, check status of client and user
# If client fails, then remediate
if [ "$Audit2_4_7" = "1" ]; then
	/usr/libexec/PlistBuddy -c "Delete :PrefKeyServicesEnabled"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist
	/usr/libexec/PlistBuddy -c "Add :PrefKeyServicesEnabled bool false"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist
	echo "$(date -u)" "2.4.7 remediated" | tee -a "$logFile"
fi

# 2.4.8 Disable File Sharing
# Verify organisational score
Audit2_4_8="$(defaults read "$plistlocation" OrgScore2_4_8)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_8" = "1" ]; then
	/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist
	/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist
	echo "$(date -u)" "2.4.8 remediated" | tee -a "$logFile"
fi

# 2.4.9 Disable Remote Management
# Verify organisational score
Audit2_4_9="$(defaults read "$plistlocation" OrgScore2_4_9)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_4_9" = "1" ]; then
	/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist
	/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
	echo "$(date -u)" "2.4.9 remediated" | tee -a "$logFile"
fi

# 2.5.1.3 Ensure all user storage CoreStorage Volumes are encrypted
# According to CIS Benchmarks for Monterey, here is the remediation:
# Use Disk Utility to erase a disk and format as macOS Extended (Journaled, Encrypted)
# 2.5.1.3 Ensure all user storage CoreStorage volumes are encrypted
echo "$(date -u)" "2.5.1.3  Not remediated, Manual Intervention required" | tee -a "$logFile"

# 2.5.2.1 Enable Gatekeeper 
# Verify organisational score
Audit2_5_2_1="$(defaults read "$plistlocation" OrgScore2_5_2_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_5_2_1" = "1" ]; then
	spctl --master-enable
	echo "$(date -u)" "2.5.2.1 remediated" | tee -a "$logFile"
fi


# 2.5.2.2 Enable Firewall 
# Remediation sets Firewall on for essential services
# Verify organisational score
Audit2_5_2_2="$(defaults read "$plistlocation" OrgScore2_5_2_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_5_2_2" = "1" ]; then
	defaults write /Library/Preferences/com.apple.alf globalstate -int 2
	echo "$(date -u)" "2.5.2.2 remediated" | tee -a "$logFile"
fi

# 2.5.2.3 Enable Firewall Stealth Mode 
# Verify organisational score
Audit2_5_2_3="$(defaults read "$plistlocation" OrgScore2_5_2_3)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_5_2_3" = "1" ]; then
	/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
	echo "$(date -u)" "2.5.2.3 remediated" | tee -a "$logFile"
fi

# 2.5.3 Enable Location Services
# Verify organisational score
Audit2_5_3="$(defaults read "$plistlocation" OrgScore2_5_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit2_5_3" = "1" ]; then
	launchctl load -w /System/Library/LaunchDaemons/com.apple.locationd.plist
	echo "$(date -u)" "2.5.3 remediated" | tee -a "$logFile"
fi

# 2.5.5 Disable sending diagnostic and usage data to Apple
# Verify organisational score
Audit2_5_5="$(defaults read "$plistlocation" OrgScore2_5_5)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_5_5" = "1" ]; then
	AppleDiagn=$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit)
	if [ $AppleDiagn == 1 ]; then 
		defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit -bool false
		/bin/chmod 644 /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist
		/usr/sbin/chgrp admin /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist
		echo "$(date -u)" "2.5.5 remediated" | tee -a "$logFile"
	fi
fi


# 2.5.6 Limit Ad tracking and personalized Ads
# Verify organisational score
Audit2_5_6="$(defaults read "$plistlocation" OrgScore2_5_6)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_5_6" = "1" ]; then
	defaults write /Users/"${currentUser}"/Library/Preferences/com.apple.AdLib.plist forceLimitAdTracking -bool true
	chown "${currentUser}":staff /Users/"${currentUser}"/Library/Preferences/com.apple.AdLib.plist
	echo "$(date -u)" "2.5.6 consider using a configuration profile" | tee -a "$logFile"
	echo "$(date -u)" "2.5.6 remediated" | tee -a "$logFile"
fi

# 2.5.7 Audit Camera Privacy and Confidentiality
echo "$(date -u)" "2.5.7  Not remediated, Check restrictions profile, valus set in audit script for true(off) or false(Allowed)" | tee -a "$logFile"

# 2.7.1 Time Machine Auto-Backup
# Verify organisational score
Audit2_7_1="$(defaults read "$plistlocation" OrgScore2_7_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_7_1" = "1" ]; then
	defaults write /Library/Preferences/com.apple.TimeMachine.plist AutoBackup 1
	echo "$(date -u)" "2.7.1 remediated" | tee -a "$logFile"
fi

# 2.8 Disable "Wake for network access"
# Verify organisational score
Audit2_8="$(defaults read "$plistlocation" OrgScore2_8)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_8" = "1" ]; then
	pmset -a womp 0
	pmset -a powernap 0
	echo "$(date -u)" "2.8 remediated" | tee -a "$logFile"
fi

# 2.9 Disable Power Nap
# Verify organisational score
Audit2_9="$(defaults read "$plistlocation" OrgScore2_9)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_9" = "1" ]; then
	pmset -a powernap 0
	echo "$(date -u)" "2.9 remediated" | tee -a "$logFile"
fi

# 3.1 Enable security auditing
# Verify organisational score
Audit3_1="$(defaults read "$plistlocation" OrgScore3_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_1" = "1" ]; then
	/bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
	echo "$(date -u)" "3.1 remediated" | tee -a "$logFile"
fi

# 3.2 Configure Security Auditing Flags
# Verify organisational score
Audit3_2="$(defaults read "$plistlocation" OrgScore3_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_2" = "1" ]; then
	cp /etc/security/audit_control /etc/security/audit_control_old
	sed "s/"flags:lo,aa"/"flags:lo,ad,fd,fm,-all"/g" /etc/security/audit_control_old > /etc/security/audit_control
	chmod 644 /etc/security/audit_control
	chown root:wheel /etc/security/audit_control
	echo "$(date -u)" "3.2 remediated" | tee -a "$logFile"
fi

# 3.3 Retain install.log for 365 or more days 
# Verify organisational score
Audit3_3="$(defaults read "$plistlocation" OrgScore3_3)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_3" = "1" ]; then
	installRetention="$(grep -i ttl /etc/asl/com.apple.install | awk -F'ttl=' '{print $2}')"
	if [[ "$installRetention" = "" ]]; then
		mv /etc/asl/com.apple.install /etc/asl/com.apple.install.old
		sed '$s/$/ ttl=365/' /etc/asl/com.apple.install.old > /etc/asl/com.apple.install
		chmod 644 /etc/asl/com.apple.install
		chown root:wheel /etc/asl/com.apple.install
		echo "$(date -u)" "3.3 remediated" | tee -a "$logfile"	
	else
	if [[ "$installRetention" -lt "365" ]]; then
		mv /etc/asl/com.apple.install /etc/asl/com.apple.install.old
		sed "s/"ttl=$installRetention"/"ttl=365"/g" /etc/asl/com.apple.install.old > /etc/asl/com.apple.install
		chmod 644 /etc/asl/com.apple.install
		chown root:wheel /etc/asl/com.apple.install
		echo "$(date -u)" "3.3 remediated" | tee -a "$logfile"	
	fi
	fi
fi

# 3.4 Ensure security auditing retention
# Verify organisational score
Audit3_4="$(defaults read "$plistlocation" OrgScore3_4)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_4" = "1" ]; then
	cp /etc/security/audit_control /etc/security/audit_control_old
	oldExpireAfter=$(cat /etc/security/audit_control | egrep expire-after)
	sed "s/${oldExpireAfter}/expire-after:60d OR 1G/g" /etc/security/audit_control_old > /etc/security/audit_control
	chmod 644 /etc/security/audit_control
	chown root:wheel /etc/security/audit_control
	echo "$(date -u)" "3.4 remediated" | tee -a "$logfile"	
fi

# 3.5 Control access to audit records
# Verify organisational score
Audit3_5="$(defaults read "$plistlocation" OrgScore3_5)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_5" = "1" ]; then
	chown -R root:wheel /var/audit
	chmod -R 440 /var/audit
	chown root:wheel /etc/security/audit_control
	chmod 400 /etc/security/audit_control
	"$(date -u)" "3.5 remediated" | tee -a "$logfile"	
fi


# 3.6 Ensure firewall is configured to log
# Verify MacOS Monterey does not allow command line editing of firewall



# 3.7 Audit Software Inventory
echo "$(date -u)" "3.7  Not remediated, Jamf Provides Inventory" | tee -a "$logFile"

# 4.1 Disable Bonjour advertising service 
# Verify organisational score
Audit4_1="$(defaults read "$plistlocation" OrgScore4_1)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit4_1" = "1" ]; then
	defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true
	echo "$(date -u)" "4.1 remediated" | tee -a "$logFile"
fi

# 4.2 Enable "Show Wi-Fi status in menu bar" 
# Verify organisational score
Audit4_2="$(defaults read "$plistlocation" OrgScore4_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit4_2" = "1" ]; then
	open "/System/Library/CoreServices/Menu Extras/AirPort.menu"
	echo "$(date -u)" "4.2 remediated" | tee -a "$logFile"
fi

# 4.3 Audit Network Specific Locations
echo "$(date -u)" "4.3  Not remediated, Corporate Managed" | tee -a "$logFile"

# 4.4 Ensure http server is not running 
# Verify organisational score
Audit4_4="$(defaults read "$plistlocation" OrgScore4_4)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit4_4" = "1" ]; then
	for x in $(ps -ax | grep http | awk '{print $1 " " $4}' | grep http | awk '{print $1}' ); do
		CountProcess=$((CountProcess+1))
		apachectl stop
		launchctl unload /System/Library/LaunchDaemons/org.apache.httpd.plist 2>/dev/null
		defaults write /var/db/com.apple.xpc.launchd/disabled.plist org.apache.httpd -bool true
	done
	
	CountProcess="0"
	for x in $(ps -ax | grep http | awk '{print $1 " " $4}' | grep http | awk '{print $1}' ); do
		if  [ "$CountProcess" == "0" ]; then
			echo "* 4.4 Ensure http server is not running" >> "$auditfilelocation"
			echo "$(date -u)" "4.4 fix" | tee -a "$logFile"; else
				echo "$(date -u)" "4.4 remediated" | tee -a "$logFile"
				$Defaults write "$plistlocation" OrgScore4_4 -bool false
		fi
	done
fi

# 4.5 Ensure nfs server is not running
# Verify organisational score
Audit4_5="$(defaults read "$plistlocation" OrgScore4_5)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit4_5" = "1" ]; then
	nfsd disable
	rm -rf /etc/exports
	echo "$(date -u)" "4.5 remediated" | tee -a "$logFile"
fi

# 4.6 Audit Wi-Fi Settings
echo "$(date -u)" "4.6  Not remediated, Security to request" | tee -a "$logFile"

# 5.1.1 Secure Home Folders
# Verify organisational score
Audit5_1_1="$(defaults read "$plistlocation" OrgScore5_1_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_1_1" = "1" ]; then
	# If client fails, then remediate
	IFS=$'\n'
	for userDirs in $( find /Users -mindepth 1 -maxdepth 1 -type d -perm -1 | grep -v "Shared" | grep -v "Guest" ); do
		chmod og-rwx "$userDirs"
	done
	echo "$(date -u)" "5.1.1 enforced" | tee -a "$logFile"
	unset IFS
fi

# 5.1.2 Ensure System Integrity Protection Status (SIPS) Is Enabled
# Verify organisational score
Audit5_1_2="$(defaults read "$plistlocation" OrgScore5_1_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_1_2" = "1" ]; then
	echo "$(date -u)" "5.1.2 System Integrity Protection Status (SIPS) must be enabled manually." | tee -a "$logFile"
fi

# 5.1.3 Ensure Apple Mobile File Integrity Is Enabled
# Verify organisational score
Audit5_1_3="$(defaults read "$plistlocation" OrgScore5_1_3)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_1_3" = "1" ]; then
	/usr/sbin/nvram boot-args=""
	echo "$(date -u)" "5.1.3 enforced" | tee -a "$logFile"
fi

# 5.1.4 Ensure Library Validation is enabled
# Verify organisational score
Audit5_1_4="$(defaults read "$plistlocation" OrgScore5_1_4)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_1_4" = "1" ]; then
	/usr/bin/defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation -bool false
	echo "$(date -u)" "5.1.4 enforced" | tee -a "$logFile"
fi

# 5.1.5 Ensure Sealed System Volume (SSV) Is Enabled
# Verify organisational score
Audit5_1_5="$(defaults read "$plistlocation" OrgScore5_1_5)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_1_5" = "1" ]; then
	echo "$(date -u)" "5.1.5 Can not be enforced, reboot to recovery mode and run 'csrutil enable authenticated-root' in Terminal." | tee -a "$logFile"
fi

# 5.1.6 formerly 5.1.6 Ensure Appropriate Permissions Are Enabled for System Wide Applications
# Verify organisational score
Audit5_1_6="$(defaults read "$plistlocation" OrgScore5_1_6)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_1_6" = "1" ]; then
	IFS=$'\n'
	for apps in $( find /Applications -iname "*\.app" -type d -perm -2 ); do
		chmod -R o-w "$apps"
	done
	echo "$(date -u)" "5.1.6 enforced" | tee -a "$logFile"
	unset IFS
fi

# 5.1.7 Ensure No World Writable Files Exist in the System Folder
echo "$(date -u)" "5.1.7  Not remediated, SIP Managed" | tee -a "$logFile"

# 5.1.8 Check Library folder for world writable files
# Verify organisational score
Audit5_1_8="$(defaults read "$plistlocation" OrgScore5_1_8)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_1_8" = "1" ]; then
	# Exempts Adobe files by default!
    # for libPermissions in $( find /Library -type d -perm -2 -ls | grep -v Caches ); do
	IFS=$'\n'
	for libPermissions in $( find /Library -type d -perm -2 | grep -v Caches | grep -v Adobe | grep -v VMware); do
		chmod -R o-w "$libPermissions"
	done
	echo "$(date -u)" "5.1.8 enforced" | tee -a "$logFile"
	unset IFS
fi

# 5.10 Require an administrator password to access system-wide preferences
# Verify organisational score
Audit5_10="$(defaults read "$plistlocation" OrgScore5_10)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_10" = "1" ]; then
	security authorizationdb read system.preferences > /tmp/system.preferences.plist
	/usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist
	security authorizationdb write system.preferences < /tmp/system.preferences.plist
	echo "$(date -u)" "5.10 remediated" | tee -a "$logFile"
fi

# 5.11 Disable ability to login to another user's active and locked session
# Verify organisational score
Audit5_11="$(defaults read "$plistlocation" OrgScore5_11)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_11" = "1" ]; then
	/usr/bin/security authorizationdb write system.login.screensaver "use-login-window-ui"
	echo "$(date -u)" "5.11 remediated" | tee -a "$logFile"
fi

# 5.12 Create a custom message for the Login Screen
# Verify organisational score
Audit5_12="$(defaults read "$plistlocation" OrgScore5_12)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_12" = "1" ]; then
	PolicyBannerText="CIS mandated Login Window banner"
	defaults write /Library/Preferences/com.apple.loginwindow.plist LoginwindowText -string "$PolicyBannerText"
	echo "$(date -u)" "5.12 remediated" | tee -a "$logFile"
fi

# 5.13 Create a Login window banner
# Policy Banner https://support.apple.com/en-us/HT202277
# Verify organisational score
Audit5_13="$(defaults read "$plistlocation" OrgScore5_13)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_13" = "1" ]; then
	PolicyBannerText="CIS mandated Login Window banner"
	/bin/echo "$PolicyBannerText" > "/Library/Security/PolicyBanner.txt"
	/bin/chmod 755 "/Library/Security/PolicyBanner."* 
	echo "$(date -u)" "5.13 remediated" | tee -a "$logFile"
fi

# 5.14 Do not enter a password-related hint (Not Scored)

# 5.15 Disable Fast User Switching (Not Scored)
# Verify organisational score
Audit5_15="$(defaults read "$plistlocation" OrgScore5_15)"
# If organisational score is 1 or true, check status of client
if [ "$Audit5_15" = "1" ]; then
	defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool false
	echo "$(date -u)" "5.15 remediated, Check Restriction Profile" | tee -a "$logFile"
fi

# 5.2.1 Ensure Password Account Lockout Threshold Is Configured
# Config Profile Only

# 5.2.2 Ensure Password Minimum Length Is Configured
# Config Profile Only

# 5.2.3 Ensure Complex Password Must Contain Alphabetic Characters Is Configured
# Config Profile Only

# 5.2.4 Ensure Complex Password Must Contain Numeric Character Is Configured
# Config Profile Only

# 5.2.5 Ensure Complex Password Must Contain Special Character Is Configured
# Config Profile Only

# 5.2.6 Ensure Complex Password Must Contain Uppercase and Lowercase Characters Is Configured
# Config Profile Only

# 5.2.7 Ensure Password Age Is Configured
# Config Profile Only

# 5.2.8 Ensure Password History Is Configured
# Config Profile Only

# 5.3 Reduce the sudo timeout period
# Verify organisational score
Audit5_3="$(defaults read "$plistlocation" OrgScore5_3)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_3" = "1" ]; then
	echo "Defaults timestamp_timeout=0" >> /etc/sudoers
	echo "$(date -u)" "5.3 remediated" | tee -a "$logFile"
fi

# 5.4 Use a separate timestamp for each user/tty combo
# Verify organisational score
Audit5_4="$(defaults read "$plistlocation" OrgScore5_4)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_4" = "1" ]; then
	sed -i ".old" '/Default !tty_tickets/d' /etc/sudoers
	chmod 644 /etc/sudoers
	chown root:wheel /etc/sudoers
	echo "$(date -u)" "5.4 remediated" | tee -a "$logFile"
fi

# 5.5 Automatically lock the login keychain for inactivity
# 5.5 Ensure login keychain is locked when the computer sleeps
# If both 5.5 and 5.5 need to be set, both commands must be run at the same time
# Verify organisational score
Audit5_5="$(defaults read "$plistlocation" OrgScore5_5)"
Audit5_5="$(defaults read "$plistlocation" OrgScore5_5)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_5" = "1" ] && [ "$Audit5_5" = 1 ]; then
echo "$(date -u)" "Checking 5.5 and 5.5" | tee -a "$logFile"
	security set-keychain-settings -l -u -t 21600s /Users/"$currentUser"/Library/Keychains/login.keychain
	echo "$(date -u)" "5.5 and 5.5 remediated" | tee -a "$logFile"
	elif [ "$Audit5_5" = "1" ] && [ "$Audit5_5" = 0 ]; then
		echo "$(date -u)" "Checking 5.5" | tee -a "$logFile"
		security set-keychain-settings -u -t 21600s /Users/"$currentUser"/Library/Keychains/login.keychain
		echo "$(date -u)" "5.5 remediated" | tee -a "$logFile"
		elif [ "$Audit5_5" = "0" ] && [ "$Audit5_5" = 1 ]; then
			echo "$(date -u)" "Checking 5.5" | tee -a "$logFile"
			security set-keychain-settings -l /Users/"$currentUser"/Library/Keychains/login.keychain
			echo "$(date -u)" "5.5 remediated" | tee -a "$logFile"
fi

# 5.6 Do not enable the "root" account
# Verify organisational score
Audit5_6="$(defaults read "$plistlocation" OrgScore5_6)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_6" = "1" ]; then
	dscl . -create /Users/root UserShell /usr/bin/false
	echo "$(date -u)" "5.6 remediated" | tee -a "$logFile"
fi

# 5.7 Disable automatic login
# Verify organisational score
Audit5_7="$(defaults read "$plistlocation" OrgScore5_7)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_7" = "1" ]; then
	defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser
	echo "$(date -u)" "5.7 remediated" | tee -a "$logFile"
fi

# 5.8 Require a password to wake the computer from sleep or screen saver
# Verify organisational score
Audit5_8="$(defaults read "$plistlocation" OrgScore5_8)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_8" = "1" ]; then
	defaults write /Users/"$currentUser"/Library/Preferences/com.apple.screensaver askForPassword -int 1
	echo "$(date -u)" "5.8 remediated" | tee -a "$logFile"
fi

# 5.9 Ensure system is set to hibernate
# Verify organisational score
Audit5_9="$(defaults read "$plistlocation" OrgScore5_9)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit5_9" = "1" ]; then
	pmset -a standbydelaylow 600
	pmset -a standbydelayhigh 600
	pmset -a highstandbythreshold 100
	pmset -a destroyfvkeyonstandby 1
	pmset -a hibernatemode 25
	echo "$(date -u)" "5.9 remediated" | tee -a "$logFile"
fi

# 6.1.1 Display login window as name and password
# Verify organisational score
Audit6_1_1="$(defaults read "$plistlocation" OrgScore6_1_1)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_1_1" = "1" ]; then
	defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true
	echo "$(date -u)" "6.1.1 remediated" | tee -a "$logFile"
fi

# 6.1.2 Disable "Show password hints"
# Verify organisational score
Audit6_1_2="$(defaults read "$plistlocation" OrgScore6_1_2)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_1_2" = "1" ]; then
	defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0
	echo "$(date -u)" "6.1.2 remediated" | tee -a "$logFile"
fi

# 6.1.3 Disable guest account
# Verify organisational score
Audit6_1_3="$(defaults read "$plistlocation" OrgScore6_1_3)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_1_3" = "1" ]; then
	defaults write /Library/Preferences/com.apple.loginwindow.plist GuestEnabled -bool false
	echo "$(date -u)" "6.1.3 remediated" | tee -a "$logFile"
fi

# 6.1.4 Disable "Allow guests to connect to shared folders"
# Verify organisational score
Audit6_1_4="$(defaults read "$plistlocation" OrgScore6_1_4)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit6_1_4" = "1" ]; then
echo "$(date -u)" "Checking 6.1.4" | tee -a "$logFile"
	afpGuestEnabled="$(defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess)"
	smbGuestEnabled="$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess)"
	if [ "$afpGuestEnabled" = "1" ]; then
		defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false
		echo "$(date -u)" "6.1.4 remediated" | tee -a "$logFile";
	fi
	if [ "$smbGuestEnabled" = "1" ]; then
		defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false
		echo "$(date -u)" "6.1.4 remediated" | tee -a "$logFile";
	fi
fi

# 6.1.5 Remove Guest home folder
# Verify organisational score
Audit6_1_5="$(defaults read "$plistlocation" OrgScore6_1_5)"
# If organisational score is 1 or true, check status of client
if [ "$Audit6_1_5" = "1" ]; then
	rm -rf /Users/Guest
	echo "$(date -u)" "6.1.5 remediated" | tee -a "$logFile"
fi

# 6.2 Turn on filename extensions
# Verify organisational score
Audit6_2="$(defaults read "$plistlocation" OrgScore6_2)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit6_2" = "1" ]; then
	sudo -u "$currentUser" defaults write NSGlobalDomain AppleShowAllExtensions -bool true
	pkill -u "$currentUser" Finder
	echo "$(date -u)" "6.2 remediated" | tee -a "$logFile"
	# defaults write /Users/"$currentUser"/Library/Preferences/.GlobalPreferences.plist AppleShowAllExtensions -bool true
fi

# 6.3 Disable the automatic run of safe files in Safari
# Verify organisational score
Audit6_3="$(defaults read "$plistlocation" OrgScore6_3)"
# If organisational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit6_3" = "1" ]; then
	/usr/libexec/PlistBuddy -c "Set :AutoOpenSafeDownloads bool false" /Users/"$currentUser"/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist
	echo "$(date -u)" "6.3 remediated" | tee -a "$logFile"
fi

echo "$(date -u)" "Remediation complete" | tee -a "$logFile"

exit 0

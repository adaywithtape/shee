#!/bin/bash
#shee.sh v0.6
#By TAPE
#Last edit 10-05-2018 22:00
#Written for the guys and gals at top-hat-sec ;)
VERS=$(sed -n 2p $0 | awk '{print $2}')    #Version information
LED=$(sed -n 4p $0 | awk '{print $3 " " $4}') #Date of last edit to script
#
#
#						TEH COLORZ :D
########################################################################
STD=$(echo -e "\e[0;0;0m")		#Revert fonts to standard colour/format
RED=$(echo -e "\e[1;31m")		#Alter fonts to red bold
REDN=$(echo -e "\e[0;31m")		#Alter fonts to red normal
GRN=$(echo -e "\e[1;32m")		#Alter fonts to green bold
GRNN=$(echo -e "\e[0;32m")		#Alter fonts to green normal
ORN=$(echo -e "\e[1;33m")		#Alter fonts to orange bold
ORNN=$(echo -e "\e[0;33m")		#Alter fonts to orange bold
BLU=$(echo -e "\e[1;36m")		#Alter fonts to blue bold
BLUN=$(echo -e "\e[0;36m")		#Alter fonts to blue normal
#
#
#						VARIABLES
########################################################################
SOUND=OFF
TUNE=/usr/share/sounds/freedesktop/stereo/complete.oga
LOG=FALSE
PCAP=FALSE
DETAIL=FALSE
UNIQUE=FALSE
SESSION_RESUME=FALSE
COLOUR=TRUE				# FALSE = no colours, TRUE = prettified output :D
if [ "$COLOUR" == "FALSE" ] ; then
read RED REDN GRN GRNN ORN ORNN BLU BLUN  <<< $(echo -e "\e[0;0;0m")
fi
#
#
#						WORKING FILES
########################################################################
LOC=/root/							# location for files to be saved
LOGTIME=$(date +"%d-%m_%H-%M-%S_")  #
LOGFILE="$LOC$LOGTIME"log_shee.log	# logfile for scans
WHITELIST="$LOC"white_shee.lst		# whitelist not to alert on
BLACKLIST="$LOC"black_shee.lst		# blacklist to alert on 
SESSION="$LOC"session_shee.lst		# working session for filtered output
TMPFILE="$LOC"tmp_shee.tmp			# temp file used to temporarily store scan results
OUI_FILE="$LOC"oui.txt				# oui.txt from ieee
if [ ! -f "$OUI_FILE" ] ; then OUI_FILE=$(locate oui.txt | tail -n 1) ; fi
if [ -f "$TMPFILE" ] ; then rm -r "$TMPFILE" ; fi
#
#
#						HEADER
########################################################################
f_header() {
echo $BLUN"     _                     _     
    | |     $STD By TAPE$BLUN      | |    
 ___| |__   ___  ___   ___| |__  
/ __| '_ \ / _ \/ _ \ / __| '_ \ 
\__ \ | | |  __/  __/_\__ \ | | |
|___/_| |_|\___|\___(_)___/_| |_|$STD"
}

#
#
#						VERSION INFO
########################################################################
f_vers() {
clear
f_header
#echo $BLUN"Seek--Hit--Eliminate--Exfiltrate"
echo $BLU">$STD Version information"
echo $STD
echo $STD"shee.sh $GRN$VERS$STD Last edit $GRN$LED$STD

Written for the THS crew at www.top-hat-sec.com
Enjoy Guyz & Galz ;)"
exit
}
#
#
#						AUTO CRUISIN'
########################################################################
f_auto() {
clear
f_header
echo $BLU">$STD Auto Cruisin' ;)"
IFACE=$(iw dev | grep Interface |  sed 's/^.*Interface //' | head -n 1)
MON_CHECK=$(iw dev $IFACE info | grep -io monitor)
if [ "$MON_CHECK" == "" ] ; then
	echo $BLU">$STD Creating monitor interface on $BLUN$IFACE$STD"
	ifconfig $IFACE down
	iwconfig $IFACE mode monitor
	ifconfig $IFACE up
	echo $BLU">$STD Monitor interface $BLUN$IFACE$STD created"
fi
echo $BLU">$STD Listen & alert on all probe requests"
echo $BLU">$STD Saving to $BLUN$LOC"$LOGTIME"log_shee.log$STD"
echo ""
printf '%-20s %-17s %-8s %-15s %-10s\n' "DATE / TIME"	"MAC ADDRESS" "POWER" "ESSID" "VENDOR INFO"
printf '%-17s %-20s %-8s %-15s %-10s\n' "--------------" "-----------------" "-----" "-----" "-----------"
if [ ! -f "$TMPFILE" ] ; then touch "$TMPFILE" ; fi
if [ ! -f "$SESSION" ] ; then
	touch "$SESSION" ; 
else cat "$SESSION" | sed '/.*".*"/d' && cat "$SESSION" | sed '/.*".*"/d' > $LOGFILE
fi
#
tshark -i $IFACE -n -l -f "subtype probereq" -T fields -e wlan.sa -e radiotap.dbm_antsignal -e wlan.ssid -E quote=d 2> /dev/null > "$TMPFILE" &\
tail -f $TMPFILE | while read line ; do 
	TIME=$(date +"%d-%m %H:%M:%S")
	MAC=$(echo $line | cut -d \" -f 2  | tr '[:lower:]' '[:upper:]')
	MAC_OUI=$(echo "$MAC" | cut -c 1-8 | sed 's/:/-/g')
	MAC_VENDOR=$(grep -i "$MAC_OUI" "$OUI_FILE" | sed -e 's/^.*(hex)//' -e 's/[ \t]*//')
	PWR=$(echo $line | cut -d \" -f 4)
	ESSID=$(echo $line | cut -d \" -f 6)
	ESSID_1=$(echo "$ESSID" | sed -e 's/^/"/' -e 's/$/"/')
	if [ "$ESSID" == "" ] ; then ESSID="no essid" ; fi
	MAC_EXIST=$(grep "$MAC" $SESSION)
	if [ "$MAC_EXIST" == "" ] ; then
	printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $SESSION
	printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID_1" "$MAC_VENDOR" >> $SESSION
	echo -e "$TIME\t$MAC\t$PWR\t$ESSID\t$MAC_VENDOR" >> $LOGFILE
	fi
	if [ "$SOUND" == "ON" ] ; then paplay "$TUNE"
	elif [ "$MAC_EXIST" != "" ] ; then
		SSID=$(echo "$MAC_EXIST" | cut -f 4)
		SSID_EXIST=$(echo "$SSID" | grep -m 1 -o "$ESSID")
		if [[ "$SSID_EXIST" != "$ESSID" ]] && [[ "$ESSID" != "no essid" ]] ; then
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $SESSION
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID_1" "$MAC_VENDOR" >> $SESSION
			if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
			echo -e "$TIME\t$MAC\t$PWR\t$ESSID\t$MAC_VENDOR" >> $LOGFILE
		fi
	fi
done
}
#
#
#						INTERFACE/MONITOR CHECK
########################################################################
f_iface_checks() {
IFACES=$(iw dev | grep Interface |  sed 's/^.*Interface //')
IFACE_CHECK=$(echo $IFACES | grep -o $IFACE)
if  [ "$IFACE" != "$IFACE_CHECK"  ] ; then
	echo $RED">$STD Input error $RED[$STD$IFACE$RED]$STD Interface not found."
	echo $STD"  Use -I option (./shee.sh -I) for list of interfaces."$STD
	exit
else
MON_CHECK=$(iw dev $IFACE info | grep -io monitor)
if [ "$MON_CHECK" == "" ] ; then
	echo $RED">$STD Interface input error $RED[$STD$IFACE$RED]$STD not in monitor mode"$STD
	exit
fi
fi
}
#
#
#						MAC ADDRESS CHECK
########################################################################
f_mac_check() {
if [[ ! "$TARGET_MAC" =~ ^[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}$ && ! "$TARGET_MAC" =~ ^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$ ]] ; then
	echo $RED">$STD Input error $RED[$STD$TARGET_MAC$RED]$STD Incorrect MAC syntax."
	exit
fi
if [[ "$TARGET_MAC" =~ ^[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}$ ]] ; then
	TARGET_MAC=$(echo "$TARGET_MAC" | sed 's/-/:/g')
fi
TARGET_MAC=$(echo "$TARGET_MAC" | tr '[:lower:]' '[:upper:]')
}
#
#
#						INTERFACE LIST/INFO
########################################################################
f_info() {
clear
f_header
echo $BLU">$STD Wireless Interface(s)"
echo $STD
AC_VERS=$(airmon-ng | sed '/^$/d' | head -n 1 | cut -f 1)
if  [ "$AC_VERS" == "PHY" ] ; then
	IFACES=$(airmon-ng | sed -e '0,/Interface/d' -e '/^$/d' | cut -f 2)
elif [ "$AC_VERS" == "Interface" ]  ; then
	IFACES=$(airmon-ng | sed -e '0,/Interface/d' -e '/^$/d' | cut -f 1)
fi
echo -e $BLUN"IFACE\t\tMAC ADDRESS\t\tSTATUS"
echo -e "-----\t\t-----------\t\t------"$STD
for i in $IFACES ; do
MAC=$(iw dev $i info | grep addr | sed 's/^.*addr //' | tr '[:lower:]' '[:upper:]' | sed 's/-/:/g')
MODE=$(iwconfig $i | grep -o Mode:.* |  awk '{print $1}')
STATUS=$(ifconfig $i |  head -n 1 | grep -io up)
if [ "$STATUS" != "UP" ] ; then STATUS=DOWN ; fi
printf '%-15s %-23s %-4s %-5s\n' "$i" "$MAC" "$STATUS" "($MODE)"
done
exit
}
#
#
#							HELP
########################################################################
f_help() {
clear
f_header
echo $BLU">$STD Help information"
echo  '
Usage: shee.sh [interface] <options>

-e   -- target ESSID probe
-h   -- this help information
-H   -- extended help
-i   -- interface to use
-m   -- target MAC adddress

EXAMPLES;
shee.sh -i wlan1mon -m 00-11-22-33-44-55
shee.sh -i wlan1mon -e "SSID HERE"
for for full help showing all options; shee.sh -H
'
exit
}
#
#
#							EXTENDED HELP
########################################################################
f_full_help() {
clear
f_header
echo $BLU">$STD Extended help information" 
echo "
d --  show details on options chosen before running script
e --  target ESSID probe
h --  help information
H --  this extended help
i --  interface to use
I --  information on available wireless interfaces
l --  log all seen MACs to pre-determined logfile
m --  target MAC adddress
M --  mode (1 6)
	  MODES
	  1  --  Listen for a specific target MAC
	  2  --  Listen for a specific target ESSID
	  3  --  Listen for all clients/probe requests
	  4  --  Listen for MACs not in a whitelist
	  5  --  Listen for MACs in a  blacklist 
r --  resume session of listening for unique MACs (for -M 3 option)
s --  sound alert on finding of (target) mac/essid.
u --  only show new clients (for -M 3 option).
U --  download latest oui.txt (mac vendor info) file from ieee.standards.org
v --  version information.
	  
USAGE EXAMPLES
list all wireless interfaces;
./shee.sh -I  

listen for specific MAC and give sound alert;
./shee.sh -i mon0 -M 1 -m 00:11:22:33:44:55 -s

listen for specific ESSID probe with sound and notification;
./shee.sh -i mon0 -M 2 -e ESSID -s -n

alert on all clients seen, show only new MACs, give sound alert and save to log.
./shee.sh -i mon0 -M 3 -usl

alert on finding Clients not in a whitelist;
./shee.sh -i mon0 -M 4

alert on finding Clients in a blacklist;
./shee.sh -i mon0 -M 5


FILES$REDN (location/names can be changed in the WORKING FILES section of the script, line 38)$STD ; 
Default location where all files created by shee.sh are stored: $GRNN$LOC$STD
Temporary file where data is written to during scans: $GRNN$TMPFILE$STD
log file      : $GRNN Date_Time_log_shee.log$STD
session file  : $GRNN$SESSION$STD
whitelist file: $GRNN$WHITELIST$STD
blacklist file: $GRNN$BLACKLIST$STD
"
}
#
#
#						MODE 1 - SPECIFIC MAC SCAN
########################################################################
f_target_mac() {
	clear
	if [ ! -f "$TMPFILE" ] ; then touch "$TMPFILE" ; fi
f_header
echo $BLU">$STD Listening for target MAC $GRN$TARGET_MAC$STD"
tshark -i $IFACE -n -l -f "subtype probereq" -T fields -e wlan.sa -e radiotap.dbm_antsignal -e wlan.ssid -E quote=d 2> /dev/null > $TMPFILE &\
tail -f $TMPFILE | while read line ; do 
MAC=$(echo $line | cut -d \" -f 2  | tr '[:lower:]' '[:upper:]')
PWR=$(echo $line | cut -d \" -f 4)
ESSID=$(echo $line | cut -d \" -f 6)
if [ "$ESSID" == "" ] ; then ESSID="no essid" ; fi
if [ "$MAC" == "$TARGET_MAC" ] ; then 
	TIME=$(date +"%Y-%m-%d %H:%M:%S")
	if [ "$LOG"  == "TRUE" ] ; then echo -e "$TIME\t$MAC\t$PWR\t$ESSID" >> $LOGFILE ; fi
	clear
	f_header && echo $BLU">$STD Listening for target MAC $GRN$TARGET_MAC$STD" 
	echo ""
	echo -ne $GRN">$STD $TIME " 
	echo "Target MAC $GRN$MAC$STD found"
	echo $GRN">$STD Probed ESSID: $GRN$ESSID$STD"
	echo $GRN">$STD RSSI: $GRN$PWR$STD" 
	f_graph
	if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi	
fi
done
}
#
#
#						MODE 2 - SPECIFIC ESSID SCAN
########################################################################
f_target_essid() {
clear
if [ ! -f "$TMPFILE" ] ; then touch "$TMPFILE" ; fi
f_header
echo -e $BLU">$STD Listening for probed essid '$GRN$TARGET_ESSID$STD'"
tshark -i $IFACE -n -l -f "subtype probereq" -T fields -e wlan.sa -e radiotap.dbm_antsignal -e wlan.ssid -E quote=d 2> /dev/null > "$TMPFILE" &\
tail -f $TMPFILE | while read line ; do 
MAC=$(echo $line | cut -d \" -f 2  | tr '[:lower:]' '[:upper:]')
PWR=$(echo $line | cut -d \" -f 4)
ESSID=$(echo $line | cut -d \" -f 6)
if [ "$ESSID" == "$TARGET_ESSID" ] ; then 
	TIME=$(date +"%Y-%m-%d %H:%M:%S")
	if [ "$LOG"  == "TRUE" ] ; then echo -e "$TIME\t$MAC\t$PWR\t$ESSID" >> $LOGFILE ; fi
	clear
	f_header && echo -e $BLU">$STD Listening for probed essid '$GRN$TARGET_ESSID$STD'"
	echo ""
	echo -ne $GRN">$STD $TIME " 
	echo "Client probing target ESSID '$GRN$ESSID$STD' found"
	echo $GRN">$STD Probed ESSID: $GRN$ESSID$STD"
	echo $GRN">$STD MAC address: $GRN$MAC$STD"
	echo $GRN">$STD RSSI: $GRN$PWR$STD" 
	f_graph
	if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
fi
done
}
#
#
#					MODE 3 - SCAN & LOG ALL CLIENT PROBE REQUESTS 
########################################################################
f_scan_all() {
clear
if [ ! -f "$TMPFILE" ] ; then touch "$TMPFILE" ; fi
f_header
echo $BLU">$STD Listen & alert on all probe requests"
echo ""
printf '%-20s %-17s %-8s %-15s %-10s\n' "DATE / TIME"	"MAC ADDRESS" "POWER" "ESSID" "VENDOR INFO"
printf '%-17s %-20s %-8s %-15s %-10s\n' "--------------" "-----------------" "-----" "-----" "-----------"
if [[ "$LOG" == "TRUE" ]] && [[ "$SESSION_RESUME" == "TRUE" ]] ; then cp "$SESSION" "$LOGFILE" ; fi
if  [[ "$UNIQUE" == "TRUE" ]]  && [[ "$SESSION_RESUME" == "TRUE" ]] ; then cat $SESSION | sed '/.*".*"/d' ; fi
tshark -i $IFACE -n -l -f "subtype probereq" -T fields -e wlan.sa -e radiotap.dbm_antsignal -e wlan.ssid -E quote=d 2> /dev/null > "$TMPFILE" &\
tail -f $TMPFILE | while read line ; do 
TIME=$(date +"%d-%m %H:%M:%S")
MAC=$(echo $line | cut -d \" -f 2  | tr '[:lower:]' '[:upper:]')
MAC_OUI=$(echo "$MAC" | cut -c 1-8 | sed 's/:/-/g')
MAC_VENDOR=$(grep -i "$MAC_OUI" "$OUI_FILE" | sed -e 's/^.*(hex)//' -e 's/[ \t]*//')
PWR=$(echo $line | cut -d \" -f 4)
ESSID=$(echo $line | cut -d \" -f 6)
ESSID_1=$(echo "$ESSID" | sed -e 's/^/"/' -e 's/$/"/')
if [ "$ESSID" == "" ] ; then ESSID="no essid" ; fi
##
# Showing all seen MACs without limiting to unique MACs
##------------------------------------------------------
if [ "$UNIQUE" == "FALSE" ] ; then 
	if [ "$LOG" == "TRUE" ] ; then 
#	echo -e "$TIME\t$MAC\t$PWR\t$ESSID" | tee -a $LOGFILE
	printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $LOGFILE
	elif [ "$LOG" == "FALSE" ] ; then
	printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" 
#	echo -e "$TIME\t$MAC\t$PWR\t$ESSID\t$MAC_VENDOR"
	fi
	if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
##
# Showing only new MACs not previously seen in the session
##--------------------------------------------------------
elif [ "$UNIQUE" == "TRUE" ] ; then
	if [ ! -f "$SESSION" ] ; then touch "$SESSION" ;  fi
	MAC_EXIST=$(grep "$MAC" $SESSION)
	if [ "$MAC_EXIST" == "" ] ; then
	printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $SESSION
	printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID_1" "$MAC_VENDOR" >> $SESSION
#		echo -e "$TIME\t$MAC\t$PWR\t$ESSID\t$MAC_VENDOR" | tee -a $SESSION
		if [ "$LOG" == "TRUE" ] ; then  echo -e "$TIME\t$MAC\t$PWR\t$ESSID\t$MAC_VENDOR" >> $LOGFILE ; fi 
		if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
	elif [ "$MAC_EXIST" != "" ] ; then
			SSID=$(echo "$MAC_EXIST" | cut -d \" -f 2)
			SSID_EXIST=$(echo "$SSID" | grep -m 1 -o "$ESSID")
			if [[ "$SSID_EXIST" != "$ESSID" ]] && [[ "$ESSID" != "no essid" ]] ; then
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $SESSION
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID_1" "$MAC_VENDOR" >> $SESSION
#			echo -e "$TIME\t$MAC\t$PWR\t$ESSID\t$MAC_VENDOR" | tee -a $SESSION
			if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
			if [ "$LOG" == "TRUE" ] ; then  printf '%-23s %-20s %-7s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" >> $LOGFILE ; fi
			fi	
	fi
fi
done
}
#
#
#					MODE 4 - SCAN/ALERT ON CLIENTS NOT IN WHITELIST 
########################################################################
f_scan_unknown() {
	clear
if [ ! -f "$WHITELIST" ] ; then touch "$WHITELIST"
	echo "#WHITELIST for shee.sh" >> $WHITELIST
	echo "#Known/Trusted WiFi Client MAC addresses" >> $WHITELIST
	echo "" >> $WHITELIST
	printf '%-20s %-20s %-20s\n' "#MAC ADDRESS" "SSID" "DESCRIPTION" >> "$WHITELIST"
	printf '%-20s %-20s %-20s\n' "#===========" "===========" "==============" >> "$WHITELIST"
	printf '%-20s %-20s %-20s\n' "00:11:22:33:44:55" "TEST_SSID" "example whitelist" >> "$WHITELIST"
	echo $RED">$STD No whitelist found, example created; $WHITELIST"
fi
if [ ! -f "$TMPFILE" ] ; then touch "$TMPFILE" ; fi	
f_header
echo $BLU">$STD Alert on clients not in whitelist"
echo ""
printf '%-20s %-17s %-8s %-15s %-10s\n' "DATE / TIME"	"MAC ADDRESS" "POWER" "ESSID" "VENDOR INFO"
printf '%-17s %-20s %-8s %-15s %-10s\n' "--------------" "-----------------" "-----" "-----" "-----------"
tshark -i $IFACE -n -l -f "subtype probereq" -T fields -e wlan.sa -e radiotap.dbm_antsignal -e wlan.ssid -E quote=d 2> /dev/null > "$TMPFILE" &\
tail -f $TMPFILE | while read line ; do 
MAC=$(echo $line | cut -d \" -f 2  | tr '[:lower:]' '[:upper:]')
MAC_OUI=$(echo "$MAC" | cut -c 1-8 | sed 's/:/-/g')
MAC_VENDOR=$(grep -i "$MAC_OUI" "$OUI_FILE" | sed -e 's/^.*(hex)//' -e 's/[ \t]*//')
ESSID=$(echo $line | cut -d \" -f 6)
if [ "$ESSID" == "" ] ; then ESSID="no essid" ; fi
ESSID_1=$(echo "$ESSID" | sed -e 's/^/"/' -e 's/$/"/')
PWR=$(echo $line | cut -d \" -f 4)
MAC_EXIST=$(grep -wi $MAC "$WHITELIST")
if [ "$MAC_EXIST" == "" ] ; then 
	TIME=$(date +"%d-%m %H:%M:%S")
##
# Showing all MACs not on whitelist without limiting to single entries
##--------------------------------------------------------------------
	if [ "$UNIQUE" == "FALSE" ] ; then 
		if [ "$LOG" == "TRUE" ] ; then 
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $LOGFILE
		elif [ "$LOG" == "FALSE" ] ; then
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" 
		fi
			if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
##
# Showing only new MACs not previously seen in the session
##--------------------------------------------------------
	elif [ "$UNIQUE" == "TRUE" ] ; then
		if [ ! -f "$SESSION" ] ; then touch "$SESSION" ;  fi
			MAC_EXIST=$(grep "$MAC" $SESSION)
			if [ "$MAC_EXIST" == "" ] ; then
				printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $SESSION
				printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID_1" "$MAC_VENDOR" >> $SESSION
				if [ "$LOG" == "TRUE" ] ; then  echo -e "$TIME\t$MAC\t$PWR\t$ESSID\t$MAC_VENDOR" >> $LOGFILE ; fi 
				if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
			elif [ "$MAC_EXIST" != "" ] ; then
				SSID=$(echo "$MAC_EXIST" | cut -d \" -f 2)
				SSID_EXIST=$(echo "$SSID" | grep -m 1 -o "$ESSID")
				if [[ "$SSID_EXIST" != "$ESSID" ]] && [[ "$ESSID" != "no essid" ]] ; then
					printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $SESSION
					printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID_1" "$MAC_VENDOR" >> $SESSION
					if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
					if [ "$LOG" == "TRUE" ] ; then  printf '%-23s %-20s %-7s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" >> $LOGFILE ; fi
				fi
			fi
		fi
	fi
done
}
#
#
#					MODE 5 - SCAN/ALERT ON CLIENTS IN BLACKLIST
########################################################################
f_scan_known() {
	clear
	if [ ! -f "$BLACKLIST" ] ; then 
	touch "$BLACKLIST"
	printf '%-20s %-20s %-20s\n' "MAC ADDRESS" "IDENTIFICATION" >> "$BLACKLIST"
	printf '%-20s %-20s %-20s\n' "-----------" "--------------" >> "$BLACKLIST"
	printf '%-20s %-20s %-20s\n' "00:11:22:33:44:55" "THAT DUDE THAT ONCE WROTE SOMETHING" >> "$BLACKLIST"
	fi
	if [ ! -f "$TMPFILE" ] ; then touch "$TMPFILE" ; fi
f_header
echo $BLU">$STD Alert on clients in blacklist" 
echo ""
printf '%-20s %-17s %-8s %-15s %-10s\n' "DATE / TIME"	"MAC ADDRESS" "POWER" "ESSID" "VENDOR INFO"
printf '%-17s %-20s %-8s %-15s %-10s\n' "--------------" "-----------------" "-----" "-----" "-----------"
tshark -i $IFACE -n -l -f "subtype probereq" -T fields -e wlan.sa -e radiotap.dbm_antsignal -e wlan.ssid -E quote=d 2> /dev/null > "$TMPFILE" &\
tail -f $TMPFILE | while read line ; do 
MAC=$(echo $line | cut -d \" -f 2  | tr '[:lower:]' '[:upper:]')
MAC_OUI=$(echo "$MAC" | cut -c 1-8 | sed 's/:/-/g')
MAC_VENDOR=$(grep -i "$MAC_OUI" "$OUI_FILE" | sed -e 's/^.*(hex)//' -e 's/[ \t]*//')
ESSID=$(echo $line | cut -d \" -f 6)
if [ "$ESSID" == "" ] ; then ESSID="no essid" ; fi
ESSID_1=$(echo "$ESSID" | sed -e 's/^/"/' -e 's/$/"/')
PWR=$(echo $line | cut -d \" -f 4)
MAC_EXIST=$(grep -wi $MAC "$BLACKLIST")
	if [ "$MAC_EXIST" != "" ] ; then 
	TIME=$(date +"%d-%m %H:%M:%S")
		if [ "$UNIQUE" == "FALSE" ] ; then 
		if [ "$LOG" == "TRUE" ] ; then 
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $LOGFILE
			echo $REDN"Information in blacklist; $GRNN$MAC_EXIST$STD"
		elif [ "$LOG" == "FALSE" ] ; then
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" 
			echo $REDN"Information in blacklist; $GRNN$MAC_EXIST$STD"
		fi
		if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
##
# Showing only new MACs not previously seen in the session
##--------------------------------------------------------
	elif [ "$UNIQUE" == "TRUE" ] ; then
		if [ ! -f "$SESSION" ] ; then touch "$SESSION" ;  fi
		MAC_EXIST1=$(grep "$MAC" $SESSION)
		if [ "$MAC_EXIST1" == "" ] ; then
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $SESSION
			printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID_1" "$MAC_VENDOR" >> $SESSION
			if [ "$LOG" == "TRUE" ] ; then  echo -e "$TIME\t$MAC\t$PWR\t$ESSID\t$MAC_VENDOR" >> $LOGFILE ; fi
			if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
		echo $REDN"Information in blacklist; $GRNN$MAC_EXIST$STD"
	elif [ "$MAC_EXIST1" != "" ] ; then
			SSID=$(echo "$MAC_EXIST1" | cut -d \" -f 2)
			SSID_EXIST=$(echo "$SSID" | grep -m 1 -o "$ESSID")
			if [[ "$SSID_EXIST" != "$ESSID" ]] && [[ "$ESSID" != "no essid" ]] ; then
				printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" "$MAC_VENDOR" | tee -a $SESSION
				printf '%-17s %-20s %-8s %-15s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID_1" "$MAC_VENDOR" >> $SESSION
				if [ "$SOUND" == "ON" ] ; then paplay "$TUNE" ; fi
				if [ "$LOG" == "TRUE" ] ; then  printf '%-23s %-20s %-7s %-10s\n' "$TIME" "$MAC" "$PWR" "$ESSID" >> $LOGFILE ; fi
				echo $REDN"Information in blacklist; $GRNN$MAC_EXIST$STD"
			fi	
	fi
	fi
fi
done
}
#
#
#					MODE 6 - AIRBASE MODE TO LOCATE CLIENT 
########################################################################
f_airbase() {
echo "airbase mode, Working on it"
exit
}
#
#
#					RSSI  POWER  GRAPH
########################################################################
f_graph()  {
echo "--------------------------------------------------"
	if [[ $PWR -le -95 && $PWR -gt -100 ]] ; then echo $RED"===$STD"
	elif [[ $PWR -le -90 && $PWR -gt -95 ]] ; then echo $RED"====$STD"
	elif [[ $PWR -le -85 && $PWR -gt -90 ]] ; then echo $RED"=======$STD"
	elif [[ $PWR -le -80 && $PWR -gt -85 ]] ; then echo $RED"==========$STD"
	elif [[ $PWR -le -75 && $PWR -gt -80 ]] ; then echo $RED"==========$ORN===$STD"
	elif [[ $PWR -le -70 && $PWR -gt -75 ]] ; then echo $RED"==========$ORN======$STD"
	elif [[ $PWR -le -65 && $PWR -gt -70 ]] ; then echo $RED"==========$ORN=========$STD"
	elif [[ $PWR -le -60 && $PWR -gt -65 ]] ; then echo $RED"==========$ORN============$STD"
	elif [[ $PWR -le -55 && $PWR -gt -60 ]] ; then echo $RED"==========$ORN================$STD"
	elif [[ $PWR -le -50 && $PWR -gt -55 ]] ; then echo $RED"==========$ORN====================$STD"
	elif [[ $PWR -le -45 && $PWR -gt -50 ]] ; then echo $RED"==========$ORN====================$GRN===$STD"
	elif [[ $PWR -le -40 && $PWR -gt -45 ]] ; then echo $RED"==========$ORN====================$GRN======$STD"
	elif [[ $PWR -le -35 && $PWR -gt -40 ]] ; then echo $RED"==========$ORN====================$GRN========$STD"
	elif [[ $PWR -le -30 && $PWR -gt -35 ]] ; then echo $RED"==========$ORN====================$GRN==========$STD"
	elif [[ $PWR -le -25 && $PWR -gt -30 ]] ; then echo $RED"==========$ORN====================$GRN=============$STD"
	elif [[ $PWR -le -20 && $PWR -gt -25 ]] ; then echo $RED"==========$ORN====================$GRN==============$STD"
	elif [[ $PWR -le -15 && $PWR -gt -20 ]] ; then echo $RED"==========$ORN====================$GRN===============$STD"
	elif [[ $PWR -le -10 && $PWR -gt -15 ]] ; then echo $RED"==========$ORN====================$GRN================$STD"
	elif [[ $PWR -le -5 && $PWR -gt -10 ]] ; then echo $RED"==========$ORN=====================$GRN=================$STD"
	elif [[ $PWR -le -1 && $PWR -gt -5 ]] ; then echo $RED"==========$ORN======================$GRN==================$STD"
	fi
echo "--------------------------------------------------"
}
#
#
#						DETAIL INFO
########################################################################
# Showing the filenames & switches used so these can be checked if getting some unexpected output.
f_detail() {
	echo "DIRECTORY/FILES"
	echo "---------------"
	echo $GRNN"DIRECTORY-----: $GRN$LOC$STD"
	echo $GRNN"LOG-----------: $GRN$LOGFILE$STD"
	echo $GRNN"SESSION-------: $GRN$SESSION$STD"
	echo $GRNN"TEMPFILE------: $GRN$TMPFILE$STD"
	echo $GRNN"WHITELIST-----: $GRN$WHITELIST$STD"
	echo $GRNN"BLACKLIST-----: $GRN$BLACKLIST$STD"
	echo $GRNN"OUI INFO FILE-: $GRN$OUI_FILE$STD"
	echo $STD""
	echo "OPTIONS"
	echo "-------"
	echo $GRNN"MONITOR IFACE-----: $GRN$IFACE$STD"
	echo $GRNN"LOG(-l)-----------: $GRN$LOG$STD"
	echo -ne $GRNN"MODE(-M)----------: $GRN$MODE$STD"
		if [ "$MODE" == "1" ] ; then echo $GRNN" (Scan for specific MAC)"
		elif [ "$MODE" == "2" ] ; then echo $GRNN" (Scan for specific ESSID)"
		elif [ "$MODE" == "3" ] ; then echo $GRNN" (Show all seen client MACs)"
		elif [ "$MODE" == "4" ] ; then echo $GRNN" (Scan/Alert on clients not in whitelist)"
		elif [ "$MODE" == "5" ] ; then echo $GRNN" (Scan/Alert on clients in blacklist)"
		fi
	echo $GRNN"SOUND(-s)---------: $GRN$SOUND$STD"
	echo $GRNN"DETAIL(-d)--------: $GRN$DETAIL$STD"
	echo $GRNN"UNIQUE(-u)--------: $GRN$UNIQUE$STD"
	echo $GRNN"SESSION RESUME(-r): $GRN$SESSION_RESUME"
	echo ""
	echo -n $GRN">$STD Hit Enter to continue/start"
read
}
#
#
#						UPDATE/DOWNLOAD OUI LIST
########################################################################
f_update() {
wget -q --tries=3 --timeout=5 --spider http://google.com
if [[ $? -eq 0 ]]; then
echo $GRN">$STD Downloading latest oui.txt file to $LOC"
wget http://standards.ieee.org/develop/regauth/oui/oui.txt -O "$LOC"oui.txt
exit
else
echo $RED">$STD You are currently offline"
fi
}
#
#
#						OPTION FUNCTIONS
########################################################################
while getopts ":ac:de:E:hHi:Ilm:M:rsuUv" opt; do
  case $opt in
	a) f_auto ;;
	d) DETAIL=TRUE ;;
	e) TARGET_ESSID=$OPTARG ;;
	h) f_help ;;
	H) f_full_help ;;
	i) IFACE=$OPTARG ;;
	I) f_info ;;
	l) LOG=TRUE ;;
	m) TARGET_MAC=$OPTARG ;;
	M) MODE=$OPTARG  ;;
	p) PCAP=TRUE ;;
	r) SESSION_RESUME=TRUE ;;
	s) SOUND=ON ;;
	u) UNIQUE=TRUE ;;
	U) UPDATE=TRUE ;;
	v) f_vers ;;
  esac
done
#
#
#						INPUT CHECKS
########################################################################
if [ $# -eq 0 ]; then clear ; f_help ; fi 								# if no entries on command line show help.
if [ "$UPDATE" == "TRUE" ]  ; then f_update ; fi						# if update option chosen; run oui update.
if [[ -n $IFACE ]] ; then f_iface_checks ; fi 							# if interface specified with -i; check interface.
if [[ -n $TARGET_MAC ]] ; then f_mac_check ; fi							# if mac specified with -m; check mac address format.
if [[ -n $TARGET_ESSID  ]] && [[ -n $TARGET_MAC ]] ; then 				# if both mac address & essid specified; error.
	echo $RED">$STD Input error $RED[$STD -e & -m $RED]$STD"
	echo "Please specify either a MAC address (with -m) or an ESSID (with -e) to check for, not both"  
	exit
fi
if [[ -n $MODE ]] && [[ -z $IFACE ]] ; then 							# check if interface specified where required.
	echo $RED">$STD Input error; all scan modes require a monitor interface to be specified."
	echo "use $GRNN./shee.sh -I$STD to see all available interfaces"
	exit
elif [[ -n $TARGET_MAC ]] && [[ -z $IFACE ]] ; then 
	echo $RED">$STD Input error; all scan modes require a monitor interface to be specified."
	echo "use $GRNN./shee.sh -I$STD to see all available interfaces"
	exit
elif [[ -n $TARGET_ESSID ]] && [[ -z $IFACE ]] ; then 
	echo $RED">$STD Input error; all scan modes require a monitor interface to be specified."
	echo "use $GRNN./shee.sh -I$STD to see all available interfaces"
	exit
fi
if [[ "$MODE" == "1" ]] && [[ -z $TARGET_MAC ]] ; then 
	echo $RED">$STD Input error; target mac mode (-M 1) requires MAC address to be specified with -m"
	exit
elif [[ "$MODE" == "2" ]] && [[ -z $TARGET_ESSID ]] ; then 
	echo $RED">$STD Input error; target essid mode (-M 2) requires ESSID to be specified with -e"
	exit
fi
#
#
#						INPUT OPTIONS
########################################################################
#
#  DETAIL/RECAP INFO
#--------------------
if [ "$DETAIL" == "TRUE" ] ; then f_detail ; fi
#
# SESSION RESUME
#---------------
if [[ "$UNIQUE" == "TRUE" ]] && [[ -f "$SESSION" ]] ; then 
	if [ "$SESSION_RESUME" == "FALSE" ] ; then rm -r "$SESSION" ; fi
fi
#						MODE SELECTION
########################################################################
if [  -z $MODE ] ; then
	if [[ -n $IFACE ]] && [[ -n $TARGET_MAC ]] ; then MODE=1
	elif [[ -n $IFACE ]] && [[ -n $TARGET_ESSID ]] ; then MODE=2
	elif [[ $# -eq 2 ]] && [[ -n $IFACE ]] ; then MODE=3
	fi
elif [ -n $MODE ] ; then 
	if  [[ ! "$MODE" =~ [1-6] ]] ; then
	echo $RED">$STD Mode input error $RED[$STD$MODE$RED]$STD, only 1-6 possible"  
	exit
	fi
fi
#
# -M MODE SELECTION
#------------------
if [ "$MODE" == "1" ] ; then f_target_mac
elif [ "$MODE" == "2" ] ; then f_target_essid
elif [ "$MODE" == "3" ] ; then f_scan_all
elif [ "$MODE" == "4" ] ; then f_scan_unknown
elif [ "$MODE" == "5" ] ; then f_scan_known
elif [ "$MODE" == "6" ] ; then f_airbase
fi
#
#
#
exit  0
# The End :)
#
# VERSION HISTORY
# ---------------
# v0.1 released May 2015
#
# v0.2 released June 12, 2015
# - Included -d switch to show details on chosen options and files before running the script. 
# - Included -u switch to only show new Clients/Probed Essids for that particular session
# - Included -l switch for log
# - Included -r switch to allow to resume a previous unique scan
#
# v0.3 released 25-07-2015
# - Improved script checks on same MACs but separate ESSIDs to avoid multiple mentions.
# - Included the vendor info (based on mac addresses first 3 octets) from information from oui.txt (standards.ieee.org)
# - Include -U switch to update the oui.txt file from standards.ieee.org
# - Fixed accidental deletion of session file when using session resume  (-r) together with detail view (-d)
# - Increased input checks
# - Included -a (auto) for teh lulz (create monitor interface on 1st interface found and start listening/logging)
# - Updated printing to screen methods to try to mminimize screen space used.
# - Fixed not saving previous session to log when starting a resumed session with logging. 
#   25-07-2015
# - Fixed error on checking whether interfaces are UP or not. Thanks to 'kcdtv' from the kali forums !
#   https://forums.kali.org/showthread.php?25922-script-Listening-for-client-mac-(wifi)-feedback-request/page2
#
# v0.4 released 10-10-2015
# - Fixed syntax error in tshark scan which for suddenly seemed to pop up preventing the tshark command from 
#   running the capture filters as required. Thanks to 'someone_else' from the kali forums !
#  
# v0.5 released 20-11-2015
# - Updated whitelist mode to mimic the same possibilities / output as the normal scan function.
# - Updated blacklist mode to mimic the same possibilities / output as the normal scan function.
# - Small edits to text / descriptions
#
# v0.6 released 10-05-2018
# - Updated the tshark command to the correct wlan.ssid instead of wlan_mgt.ssid following a change.
# - Updated the method of checking MAC address to compensate for changes in ifconfig output by using iw dev
# - Update the method of checking whether interface is up or down following changes in ifconfig output.
#
#
# To Do List;
#============
#
# - add -p switch for saving to pcap ?
# - include 'first seen / last seen' when using -M3 ?
# - alter -M1 -M2 outputs to show a history of signal strength for better 'tracking' ?
# - catsmash logs; cat *_shee.log > log.txt | awk -F"," '!_[$3]++'

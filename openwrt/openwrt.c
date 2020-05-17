/* Copyright 2018 osMUD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * OpenWRT specific implementation of MUD rulesets
 */


/* Import function prototypes acting as the implementation interface
 * from the osmud manager to a specific physical device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include "../mudparser.h"
#include "../mud_manager.h"
#include "../oms_utils.h"
#include "../oms_messages.h"
#include "openwrt.h"

#define BUFSIZE 4096

//TODO: This needs to change into a custom UCI c-library implementation (https://lxr.openwrt.org/source/uci/)

char *getProtocolName(const char *protocolNumber)
{
	if (!protocolNumber)
		return "all";

	if (!strcmp(protocolNumber, "all")) {
		return "all";
	} else if (!strcmp(protocolNumber, "6")) {
		return "tcp";
	} else if (!strcmp(protocolNumber, "17")) {
		return "udp";
	} else {
		return "none";
	}
}

char *getActionString(const char *mudAction)
{
	if (!strcmpi(mudAction, "reject")) {
		return "REJECT";
	} else if (!strcmpi(mudAction, "accept")) {
		return "ACCEPT";
	} else {
		return "DROP";
	}
}

char *getProtocolFamily(const char *aclType)
{
	if (!aclType)
		return "all";

	if (!strcmpi(aclType, "all")) {
		return "all";
	} else if (!strcmpi(aclType, "ipv6-acl")) {
		return "ipv6";
	} else {
		return "ipv4";
	}
}

int installFirewallIPRule(char *srcIp, char *destIp, char *destPort, char *srcDevice,
		char *destDevice, char *protocol, char *ruleName, char *fwAction, char *aclType,
		char *hostName)
{
	char execBuf[BUFSIZE] = {0};
	int retval;

	/* //TODO: We need to turn srcDevice & destDevice into the real values on the router */
	/*       by default they are "lan" and "wan" but can be changed. You can find this   */
	/*       with command "uci show dhcp.lan.interface" ==> dhcp.lan.interface='lan'     */
	/*       We should update the script to pull this value from UCI                     */
	/*       EX: uci show dhcp.lan.interface | awk -F = '{print $2}'                     */
	/* NOTE: Currently we are not restricting by source-port. If needed, add this as an arg */
	snprintf(execBuf, BUFSIZE, "%s -s %s -d %s -i %s -a any -j %s -b %s -p %s -n %s -t %s -f %s -c %s", UCI_FIREWALL_SCRIPT, srcDevice, destDevice, srcIp,
			destIp, destPort, getProtocolName(protocol),
			ruleName,
			getActionString(fwAction),
			getProtocolFamily(aclType),
			hostName);

	logMsg(OMS_DEBUG, execBuf);
	retval = system(execBuf);

	if (retval) {
		logMsg(OMS_ERROR, execBuf);
	}
	return retval;
}

int removeFirewallIPRule(char *ipAddr, char *macAddress)
{
	char execBuf[BUFSIZE] = {0};
	int retval;

	snprintf(execBuf, BUFSIZE, "%s -i %s -m %s", UCI_FIREWALL_REMOVE_SCRIPT, ipAddr, macAddress);

	logMsg(OMS_DEBUG, execBuf);
	retval = system(execBuf);

	if (retval) {
		logMsg(OMS_ERROR, execBuf);
	}
	return retval;

}

int commitAndApplyFirewallRules()
{
	int retval;

	logMsg(OMS_INFO, UCI_FIREWALL_COMMIT_SCRIPT);
	retval = system(UCI_FIREWALL_COMMIT_SCRIPT);

	if (retval) {
		logMsg(OMS_ERROR, UCI_FIREWALL_COMMIT_SCRIPT);
	}
	return retval;
}

int rollbackFirewallConfiguration()
{
	int retval;

	logMsg(OMS_WARN, UCI_FIREWALL_ROLLBACK_SCRIPT);
	retval = system(UCI_FIREWALL_ROLLBACK_SCRIPT);

	if (retval) {
		logMsg(OMS_ERROR, UCI_FIREWALL_ROLLBACK_SCRIPT);
	}
	return retval;
}

int installMudDbDeviceEntry(char *mudDbDir, char *ipAddr, char *macAddress, char *mudUrl, char *mudLocalFile, char *hostName)
{
//	char execBuf[BUFSIZE] = {0};
	int retval;
	char filePath[1024] = {0};
	char line[1024] = {0};
	sprintf(filePath, "%s/%s", mudDbDir, MUD_STATE_FILE);
	sprintf(line, "%s|%s|%s|%s|%s", ipAddr, macAddress,
		(mudUrl?mudUrl:"-"), (mudLocalFile?mudLocalFile:"-"), (hostName?hostName:"-"));

	char msgBuf[1024] = {0};
	char *format = "installMudDbDeviceEntry:::Adding entry(to MudDbFile:[%s]) for device:IP[%s],MAC[%s]";
	sprintf(msgBuf, format, line, filePath, ipAddr, macAddress);
	logMsg(OMS_INFO, msgBuf);

	retval = appendLineToFile(filePath, line);
	return retval;
///Old code:
//////////////////////////////////////////////////////////
/*
	snprintf(execBuf, BUFSIZE, "%s -d %s%s -i %s -m %s -c %s -u %s -f %s", MUD_DB_CREATE_SCRIPT, mudDbDir, MUD_STATE_FILE, ipAddr,
			macAddress,
			(hostName?hostName:"-"),
			(mudUrl?mudUrl:"-"),
			(mudLocalFile?mudLocalFile:"-"));

	logMsg(OMS_DEBUG, execBuf);
	retval = system(execBuf);

	if (retval) {
		logMsg(OMS_ERROR, execBuf);
	}
	return retval;
*/
}

int removeMudDbDeviceEntry(char *mudDbDir, char *ipAddr, char *macAddress)
{
	//char execBuf[BUFSIZE] = {0};
	int retval;
	char filePath[1024] = {0};
	char ipAndMac[100] = {0};
	sprintf(filePath, "%s/%s", mudDbDir, MUD_STATE_FILE);
	sprintf(ipAndMac, "%s|%s|", ipAddr, macAddress);
	
	char msgBuf[1024] = {0};
	char *format = "removeMudDbDeviceEntry:::Removing entry(from MudDbFile:[%s]) for device:IP[%s],MAC[%s]";
	sprintf(msgBuf, format, filePath, ipAddr, macAddress);
	logMsg(OMS_INFO, msgBuf);

	retval = deleteLinesThatContainsStrFromFile(filePath, ipAndMac);
	return retval;
///Old code:
//////////////////////////////////////////////////////////
/*
	snprintf(execBuf, BUFSIZE, "%s -d %s/%s -i %s -m %s", MUD_DB_REMOVE_SCRIPT, mudDbDir, MUD_STATE_FILE, ipAddr, macAddress);

	logMsg(OMS_DEBUG, execBuf);
	retval = system(execBuf);

	if (retval) {
		logMsg(OMS_ERROR, execBuf);
	}
	return retval;
*/
}


//TODO: threadsafe with regard to read/write operations on the dnsFileName
// Appends a DNS entry to the DNS whitelist
int addDnsToDeviceDnsWhitelistFile(char *targetDomainName, char *srcIpAddr, char *srcMacAddr, char *srcHostName, char *dnsFileNameWithPath)
{
	char msgBuf[1024] = {0};
	char line[1024] = {0};
	char *format;

	sprintf(line, "%s|%s|%s|%s", targetDomainName, srcIpAddr, srcMacAddr, (srcHostName?srcHostName:"-"));
	if(isFileContainsStr(dnsFileNameWithPath, line))
	{
		format = "addDnsToDeviceDnsWhitelistFile:::DNSRule[%s] is already in file[%s]";
		sprintf(msgBuf, format, line, dnsFileNameWithPath);
		logMsg(OMS_INFO, msgBuf);
		return 1;
	}

	if(!appendLineToFile(dnsFileNameWithPath, line))
	{		
		format = "addDnsToDeviceDnsWhitelistFile:::Cannot write DNSRule to file!!!";
		logMsg(OMS_ERROR, msgBuf);
		return 0;
	}

	format = "addDnsToDeviceDnsWhitelistFile:::Successfully added DNSRule[%s] to file[%s]";
	sprintf(msgBuf, format, line, dnsFileNameWithPath);
	logMsg(OMS_INFO, msgBuf);
	return 1;
}

//TODO: threadsafe with regard to read/write operations on the dnsFileName
// Removes a DNS entry from the DNS whitelist
int removeDeviceFromDnsWhitelistFile(char *srcIpAddr, char *srcMacAddr, char *dnsFileNameWithPath)
{
	int retval = 0;
	char line[1024] = {0};
	char msgBuf[1024] = {0};
	char *format;

	sprintf(line, "|%s|%s|", srcIpAddr, srcMacAddr);

	format = "removeDeviceFromDnsWhitelistFile:::Removing (from file:[%s]), device:IP[%s],MAC[%s]";
	sprintf(msgBuf, format, dnsFileNameWithPath, srcIpAddr, srcMacAddr);
	logMsg(OMS_INFO, msgBuf);

	retval = deleteLinesThatContainsStrFromFile(dnsFileNameWithPath, line);

	return retval;
}

int verifyCmsSignature(char *mudFileLocation, char *mudSigFileLocation)
{
	/* openssl cms -verify -in mudfile.p7s -inform DER -content badtxt */

	char execBuf[BUFSIZE] = {0};
	int retval, sigStatus;

	snprintf(execBuf, BUFSIZE, "openssl cms -verify -in %s -inform DER -content %s -purpose any", mudSigFileLocation, mudFileLocation);

	logMsg(OMS_DEBUG, execBuf);
	retval = system(execBuf);

	/* A non-zero return value indicates the signature on the mud file was invalid */
	if (retval) {
		logMsg(OMS_ERROR, execBuf);
		sigStatus = INVALID_MUD_FILE_SIG;
	}
	else {
		sigStatus = VALID_MUD_FILE_SIG;
	}

	return sigStatus;

}

/*
 * Creates the MUD storage location on the device filesystem
 * Return 0 on success, or non-zero if creation (of at least one dir in path) fails.
 */
int createMudfileStorage(char *mudFileDataLocationInfo)
{
	return mkdir_path(mudFileDataLocationInfo); // similiar to command "mkdir -p path"
}

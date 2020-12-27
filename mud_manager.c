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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>

#include "mud_manager.h"
#include "oms_messages.h"
#include "comms.h"
#include "oms_utils.h"
#include "dhcp_event.h"
#include "mudparser.h"


#define PORT_BUF_SIZE 512


extern char *dnsWhiteListFile;
extern int noFailOnMudValidation;

int dhcpNewEventCount = 0;
int dhcpOldEventCount = 0;
int dhcpDeleteEventCount = 0;
int dhcpErrorEventCount = 0;

void resetDhcpCounters()
{
	dhcpNewEventCount = 0;
	dhcpOldEventCount = 0;
	dhcpDeleteEventCount = 0;
	dhcpErrorEventCount = 0;
}

void buildDhcpEventsLogMsg(char *buf, int bufSize)
{
	snprintf(buf, bufSize, "OSMUD:DHCP Stats: New: %d | Old: %d | Delete: %d | Errors: %d",
			dhcpNewEventCount, dhcpOldEventCount, dhcpDeleteEventCount, dhcpErrorEventCount);
	buf[bufSize-1] = '\0';
}

int buildPortRange(char *portBuf, int portBufSize, AceEntry *ace)
{
	int retval = 0; /* Return > 0 if there is an error with port assignments */

	snprintf(portBuf, portBufSize, "%s:%s", ace->lowerPort, ace->upperPort);
	portBuf[portBufSize-1] = '\0';

	return retval;
}

int processFromAccess(char *aclName, char *aclType, AclEntry *acl, DhcpEvent *event)
{
	int retval = 0;
	int actionResult = 0;
	int i, j;
	DomainResolutions *dnsInfo;
	char portRangeBuffer[PORT_BUF_SIZE];
	char *msg;

	if (!acl)
	{
		msg = "processFromAccess:::ERROR: NULL in *from* acl rule";
		logMsg(OMS_CRIT, msg);
		return 1;  /* It's an error situation */
	}

	for (i = 0; i < acl->aceCount; i++)
	{
		if (acl->aceList[i].aceType != ACLDNS)
		{
			msg = "processFromAccess:::Ignoring unimplemented (not DNS) *from* ace rule.";
			logMsg(OMS_WARN, msg);
			continue;
		}

		/* This is A DNS rule and not static-ip/same-manufacture/other rule. */
		msg = "processFromAccess:::Applying *from* DNS ace rule";
    		logMsg(OMS_INFO, msg);

    		dnsInfo = resolveDnsEntryToIp(acl->aceList[i].dnsName);

    		// Need to check a return code to make sure the rule got applied correctly
    		addDnsToDeviceDnsWhitelistFile(dnsInfo->domainName, event->ipAddress, event->macAddress,
				event->hostName, dnsWhiteListFile);

    		// Need to install a firewall rule for each IP that resolves
    		for (j = 0; j < dnsInfo->ipCount; j++)
		{
    			buildPortRange(portRangeBuffer, PORT_BUF_SIZE, &(acl->aceList[i]));
    			actionResult = installFirewallIPRule(event->ipAddress,
							dnsInfo->ipList[j],
							portRangeBuffer,
							LAN_DEVICE_NAME,
							isPrivateIP(dnsInfo->ipList[j]) ? LAN_DEVICE_NAME : WAN_DEVICE_NAME,
							acl->aceList[i].protocol,
							acl->aceList[i].ruleName,
							acl->aceList[i].actionsForwarding,
							aclType, event->hostName);
			if (actionResult)
			{
				actionResult = 0; // reset it for next rules
				msg = "processFromAccess:::Firewall *from* rule installation failed!!!";
				logMsg(OMS_CRIT, msg);
				retval = 1; /* Set flag to indicate at least one firewall rule installation failed */
			}
    		}
		freeDnsInfo(dnsInfo);
	}

	return retval;
}


int processToAccess(char *aclName, char *aclType, AclEntry *acl, DhcpEvent *event) {
	int retval = 0;
	int actionResult = 0;
	int i, j;
	DomainResolutions *dnsInfo;
	char portRangeBuffer[PORT_BUF_SIZE];
	char *msg;

	if (!acl)
	{
		msg = "processToAccess:::ERROR: NULL in *to* acl rule";
		logMsg(OMS_CRIT, msg);
		return 1;  /* It's an error situation */
	}

	for (i = 0; i < acl->aceCount; i++)
	{
		if (acl->aceList[i].aceType != ACLDNS)
		{
			msg = "processToAccess:::Ignoring unimplemented (not DNS) *to* ace rule.";
			logMsg(OMS_WARN, msg);
			continue;
		}

		/* This is A DNS rule and not static-ip/same-manufacture/other rule. */
		msg = "processToAccess:::Applying *to* DNS ace rule";
    		logMsg(OMS_INFO, msg);

    		dnsInfo = resolveDnsEntryToIp(acl->aceList[i].dnsName);

    		//TODO: Need to check a return code to make sure the rule got applied correctly
    		addDnsToDeviceDnsWhitelistFile(dnsInfo->domainName, event->ipAddress, event->macAddress,
				event->hostName, dnsWhiteListFile);

    		// Need to install a firewall rule for each IP that resolves
    		for (j = 0; j < dnsInfo->ipCount; j++) {
    			buildPortRange(portRangeBuffer, PORT_BUF_SIZE, &(acl->aceList[i]));
    			actionResult = installFirewallIPRule(	dnsInfo->ipList[j], /* srcIp */
								event->ipAddress, /* destIp */
								portRangeBuffer, /* destPort */
								isPrivateIP(dnsInfo->ipList[j]) ? LAN_DEVICE_NAME : WAN_DEVICE_NAME, /* srcDevice - lan or wan */
								LAN_DEVICE_NAME, /* destDevice - lan or wan */
								acl->aceList[i].protocol, /* protocol - tcp/udp */
								acl->aceList[i].ruleName, /* rule name */
							acl->aceList[i].actionsForwarding, /* ACCEPT/REJECT/DROP */
								aclType,
								event->hostName	/* hostname of the new device */ );
			if (actionResult)
			{
				actionResult = 0; // reset it for next rules
				msg = "processToAccess:::Firewall *from* rule installation failed!!!";
				logMsg(OMS_CRIT, msg);
				retval = 1; /* Set flag to indicate at least one firewall rule installation failed */
			}
    		}
    		freeDnsInfo(dnsInfo);
	}

	return retval;
}

//this method replaces MUD_ENDPOINT_PLACEHOLDER with asdd32d.avrahamshalev.com only if needed


	//run replace_all_placeholders.sh:
	//1.extract Company from url ($1 parameter) with awk https:// and /
	//2.search UDIDs.txt for suitable row (Company:fullDomainToReplace:<(optional)dnsServerToQueryThisDomain)
	//3.give step2 output as an input to another awk to retreive fullDomainToReplace
	//4.run command: sed -i 's/old-text/new-text/g' on file mudFileLocal ($2 parameter)
	///////////////
	//replace_all_placeholders.sh script should look like this:
	//     MUD_URL = $1
	//     MUD_LOCAL_FILE_PATH = $2
	//1  . echo MUD_URL | awk -F https:// {print $2} | awk -F / {print $1} -> Company
	//2+3. cat UDIDs.txt | awk -F Company: {print $2} | awk -F : {print $1} -> fullDomainToReplace
	//4  . sed -i 's/$$owner-unique-domain$$/fullDomainToReplace/g' MUD_LOCAL_FILE_PATH

int replaceMudPlaceholders(char *mudFileUrl, char *mudFileLocal)
{
	logMsg(OMS_INFO, "replaceMudPlaceholders::: START");
	
	//hasPlaceholders is 1/true (ONLY!) if MUD File needs to place user-unique-domain that is dynamic
	int hasPlaceholders = isFileContainsStr(mudFileLocal, MUD_ENDPOINT_PLACEHOLDER);
	if(!hasPlaceholders)
	{
		logMsg(OMS_INFO, "replaceMudPlaceholders::: END. Device's MUD File has no placeholders --> it is not going to be linked to a unique domain");
		return 0;
	}

	logMsg(OMS_INFO, "replaceMudPlaceholders::: Device's MUD File has placeholders --> searching for it's most suitable unique domain!");
	char *company = getCompanyFromUrl(mudFileUrl);//TODO: check implementation : the bottom free on this char*
	DomainResolutions *dnsRes = getMostSuitableDomainResolution(company);

logMsg(OMS_INFO, "replaceMudPlaceholders:::Found the most suitable unique domain. Going to replace placeholders to the suitable unique domain..");
	replaceTextInFile(mudFileLocal, MUD_ENDPOINT_PLACEHOLDER, dnsRes->domainName);

	logMsg(OMS_DEBUG, "replaceMudPlaceholders:::Finished replacing. Calling safe_free()");	
	safe_free(company);
	
	logMsg(OMS_DEBUG, "replaceMudPlaceholders::: END. After calling safe_free()");

	return hasPlaceholders;
}

int parseMudAndExecuteRules(DhcpEvent *dhcpEvent)
{
	int i;
	char *msg;
	int actionResult = 0;
	int retval = 0; // non-zero means errors.

	logMsg(OMS_DEBUG, "parseMudAndExecuteRules::: START");
	
	MudFileInfo *mudFile = parseMudFile(dhcpEvent->mudFileStorageLocation);
	// Loop over mud file and carry out actions
	if (!mudFile)
	{
		msg = "parseMudAndExecuteRules:::ERROR:END. Problems parsing MUD File - no rules installed!!!!!";
		logMsg(OMS_CRIT, msg);
		retval = 1;
		return retval;
	}

	// Mud File was parsed and ok
	// First, remove any prior entry for this device
	removeFirewallIPRule(dhcpEvent->ipAddress, dhcpEvent->macAddress);

	// Second, iterate over the MUD file and apply new rules
	// Apply fromDevice rules
	for (i = 0; i < mudFile->fromAccessListCount; i++) {
		if (!processFromAccess(mudFile->fromAccessList[i].aclName,
				mudFile->fromAccessList[i].aclType,
				getMudFileAcl(mudFile->fromAccessList[i].aclName, mudFile),
				dhcpEvent))
		{
			msg = "parseMudAndExecuteRules:::Successfully installed fromAccess rule";
			logMsg(OMS_INFO, msg);
		}
		else
		{
			msg = "parseMudAndExecuteRules:::ERROR:Problems installing fromAccess rule";
			logMsg(OMS_CRIT, msg);
			retval = 1;
		}
	}

	// Apply toDevice rules
	for (i = 0; i < mudFile->toAccessListCount; i++) {
		if (!processToAccess(mudFile->toAccessList[i].aclName,
				mudFile->toAccessList[i].aclType,
				getMudFileAcl(mudFile->toAccessList[i].aclName, mudFile),
				dhcpEvent))
		{
			msg = "parseMudAndExecuteRules:::Successfully installed toAccess rule";
			logMsg(OMS_INFO, msg);
		}
		else
		{
			msg = "parseMudAndExecuteRules:::ERROR:sProblems installing toAccess rule";
			logMsg(OMS_CRIT, msg);
			retval = 1;
		}
	}

	// Install default rule to block all traffic from this IP address unless allowed in the MUD file
	// ORDER MATTERS - this rule needs to be installed after all of the individual allow/disallow rules
	actionResult = installFirewallIPRule(	dhcpEvent->ipAddress, 	/* srcIp */
						"any",			/* destIp */
						"any",			/* destPort */
						LAN_DEVICE_NAME,	/* srcDevice - lan or wan */
						WAN_DEVICE_NAME,	/* destDevice - lan or wan */
						"all",			/* protocol - tcp/udp/icmp */
						"REJECT-ALL",		/* rule name //TODO: name by device name */
						"DROP",			/* ACCEPT or DROP or REJECT */
						"all",			/* */
						dhcpEvent->hostName	/* hostname of the device */ );
	if (actionResult)
	{
		msg = "parseMudAndExecuteRules:::ERROR:Problems installing default WAN restrict rule!!!";
		logMsg(OMS_CRIT, msg);
		retval = 1;
	}
	actionResult = installFirewallIPRule("any", 	/* srcIp */
						dhcpEvent->ipAddress,		/* destIp */
						"any",			/* destPort */
						LAN_DEVICE_NAME,	/* srcDevice - lan or wan */
						LAN_DEVICE_NAME,	/* destDevice - lan or wan */
						"all",			/* protocol - tcp/udp/icmp */
						"REJECT-ALL",		/* rule name //TODO: name by device name */
						"DROP",			/* ACCEPT or DROP or REJECT */
						"all",			/* */
						dhcpEvent->hostName	/* hostname of the device */);
	if (actionResult)
	{
		msg = "parseMudAndExecuteRules:::ERROR:Problems installing default LAN (to device) restrict rule!!!";
		logMsg(OMS_CRIT, msg);
		retval = 1;
	}
	// Lastly, commit rules and restart the firewall subsystem
	if (retval == 0)
	{
		msg = "parseMudAndExecuteRules:::Rules updated successfully-Calling commitAndApplyFirewallRules()!";
		logMsg(OMS_INFO, msg);
		commitAndApplyFirewallRules();
	}
	else
	{	/* retval=1, which means something went wrong */
		msg = "parseMudAndExecuteRules:::Errors occured-Calling rollbackFirewallConfiguration()!!!";
		logMsg(OMS_WARN, msg);
		rollbackFirewallConfiguration();
	}

	logMsg(OMS_DEBUG, "parseMudAndExecuteRules::: END");
	return retval;
}

/*
 * This takes a DHCP event and performs the following:
 * 1) Validates the MUD file (maybe via yanglint when spec is finalized)
 * 2) parses the MUD file into a OSMUD data structure representing the MUD file
 * 3) Calls the device specific implementations to implement the features in the mud file
 */
void handleNewDevice(DhcpEvent *dhcpEvent)
{
	char *msg;
	char msgBuf[1024] = {0};

	logMsg(OMS_DEBUG, "handleNewDevice::: START");

	if(!(dhcpEvent))
	{
		msg = "handleNewDevice:::WARNING:dhcpEvent is empty!!!";
		logMsg(OMS_WARN, msg);
		return;
	}
	if(!(dhcpEvent->mudFileURL))
	{
		/* This is a legacy non-MUD aware device */
		msg = "handleNewDevice::: This is a LEGACY DEVICE -- no mud file declared";
		logMsg(OMS_INFO, msg);
		doDhcpLegacyAction(dhcpEvent);
		
		msg = "handleNewDevice::: Adding DeviceEntry to MudDbStateFile..";
		logMsg(OMS_DEBUG, msg);

		installMudDbDeviceEntry(mudFileDataDirectory, dhcpEvent->ipAddress, dhcpEvent->macAddress,
					NULL, NULL, dhcpEvent->hostName);

		msg = "handleNewDevice::: END. Added DeviceEntry to MudDbStateFile";
		logMsg(OMS_DEBUG, msg);
		return;
	}

	/* This is a MUD-device and it is going to be installed with it's Mud File */


	 /* //TODO: 	This is a potential security flaw!
	 * 		its not good that the local mud-file-name of the device is only the 
	 * 		need to concat it to some other random string, so that no attacker
	 *		could name another mud file on it's private server with the same file name
	 * 		and the original mud file will be overwritten 
	*/	
	dhcpEvent->mudFileStorageLocation = createStorageLocation(dhcpEvent->mudFileURL);
	
	msg = "handleNewDevice::: This is a MUD Device. Going to download it's mud file into local file path[%s]";
	sprintf(msgBuf, msg, dhcpEvent->mudFileStorageLocation);
	logMsg(OMS_DEBUG, msgBuf);

	/* Download Mud File */
	if (getOpenMudFile(dhcpEvent->mudFileURL, dhcpEvent->mudFileStorageLocation) != 0)
	{
		msg = "handleNewDevice:::CRITIC ERROR: END. Cannot download MUD File!!!";
		logMsg(OMS_CRIT, msg);
		return;
	}
	
	/* Replace placeholders inside Mud File Rules if exist, and link device to suitable company */
	if(replaceMudPlaceholders(dhcpEvent->mudFileURL, dhcpEvent->mudFileStorageLocation))
	{
		linkDeviceToItsCompany(dhcpEvent);//TODO: check implementation!!!
	}
	
	/* Install downloaded Mud File Rules and if success write it to mudDbFile */
	if(parseMudAndExecuteRules(dhcpEvent) == 0)
	{
		installMudDbDeviceEntry(mudFileDataDirectory,
				dhcpEvent->ipAddress, dhcpEvent->macAddress,
				dhcpEvent->mudFileURL, dhcpEvent->mudFileStorageLocation,
				dhcpEvent->hostName);
	}

	logMsg(OMS_DEBUG, "handleNewDevice::: END");
}

void executeNewDhcpAction(DhcpEvent *dhcpEvent)
{
	logMsg(OMS_INFO, "executeNewDhcpAction::: START");

	char msgBuf[1024] = {0};
	buildDhcpEventContext(msgBuf, "NEW", dhcpEvent);
	logMsg(OMS_INFO, msgBuf);

	handleNewDevice(dhcpEvent);

	logMsg(OMS_INFO, "executeNewDhcpAction::: END");
}

void executeOldDhcpAction(DhcpEvent *dhcpEvent)
{
	char msgBuf[1024] = {0};
	buildDhcpEventContext(msgBuf, "OLD", dhcpEvent);
	logMsg(OMS_INFO, msgBuf);
}

void executeDelDhcpAction(DhcpEvent *dhcpEvent)
{
	char *msg;
	char msgBuf[1024] = {0};
	buildDhcpEventContext(msgBuf, "DEL", dhcpEvent);
	logMsg(OMS_INFO, msgBuf);

	if (dhcpEvent)
	{
		msg = "executeDelDhcpAction:::Deleting device: IP[%s],MAC[%s]";
		sprintf(msgBuf, msg, dhcpEvent->ipAddress, dhcpEvent->macAddress);
		logMsg(OMS_INFO, msgBuf);

		unlinkDeviceFromItsCompany(dhcpEvent);
		removeFirewallIPRule(dhcpEvent->ipAddress, dhcpEvent->macAddress);
		commitAndApplyFirewallRules();
		/* //TODO: check implementation!!! */
		removeMudDbDeviceEntry(mudFileDataDirectory, dhcpEvent->ipAddress, dhcpEvent->macAddress);
		removeDeviceFromDnsWhitelistFile(dhcpEvent->ipAddress, dhcpEvent->macAddress, dnsWhiteListFile);
	}
}

void executeOpenMudDhcpAction(DhcpEvent *dhcpEvent)
{
	char *msg;

	logMsg(OMS_INFO, "executeOpenMudDhcpAction::: START");
	if (dhcpEvent) {
		switch (dhcpEvent->action) {
			case NEW:
				dhcpNewEventCount++;
				executeNewDhcpAction(dhcpEvent);
				break;
			case OLD:
				dhcpOldEventCount++;
				executeOldDhcpAction(dhcpEvent);
				break;
			case DEL:
				dhcpDeleteEventCount++;
				executeDelDhcpAction(dhcpEvent);
				break;
			default:
				dhcpErrorEventCount++;
				msg = "executeOpenMudDhcpAction::: Bad dhcp event action code.no action taken.";
				logMsg(OMS_WARN, msg);
		}
	}

	logMsg(OMS_INFO, "executeOpenMudDhcpAction::: END");
}

DomainResolutions *resolveDnsEntryToIp(char *hostname)
{
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in *h;
	int rv;
	DomainResolutions *existingDnsRes;
	DomainResolutions *dnsRes;
	char msgBuf[1024] = {0};
	char *format;

	sprintf(msgBuf, "resolveDnsEntryToIp:::Resolving [%s]", hostname);
	logMsg(OMS_DEBUG, msgBuf);

	dnsRes = (DomainResolutions *)safe_malloc(sizeof(DomainResolutions));
	memset((void*)dnsRes, 0, sizeof(DomainResolutions));
	dnsRes->domainName = copystring(hostname);

	existingDnsRes = getDomainResolution(hostname, NULL);
	if(existingDnsRes) /* if already existing so do not resolve...take resolution from UDomainsManager. */
	{
		sprintf(msgBuf, "resolveDnsEntryToIp:::hostname [%s] was received from UDomainsManager", hostname);
		logMsg(OMS_DEBUG, msgBuf);

		dnsRes->ipCount = existingDnsRes->ipCount;

		sprintf(msgBuf, "resolveDnsEntryToIp:::Extracting All UDomain's IPs (count=[%d])", dnsRes->ipCount);
		logMsg(OMS_DEBUG, msgBuf);

		for(int i=0;i < dnsRes->ipCount; i++)
		{
			dnsRes->ipList[i] = copystring(existingDnsRes->ipList[i]);

			format = "resolveDnsEntryToIp:::IP #[%d]/#[%d] is [%s])";
			sprintf(msgBuf, format, i+1, dnsRes->ipCount, dnsRes->ipList[i]);
			logMsg(OMS_DEBUG, msgBuf);
		}

		return dnsRes;
	}


	/* If you got here then this is just a regular DNS query */
	format = "resolveDnsEntryToIp:::hostname [%s] was not received from UDomainsManager. Querieng For IPs..";
	sprintf(msgBuf, format, hostname);
	logMsg(OMS_DEBUG, msgBuf);

	dnsRes->ipCount = 0;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
	hints.ai_socktype = SOCK_STREAM;

	if ( (rv = getaddrinfo( hostname , "http" , &hints , &servinfo)) != 0)
	{
		sprintf(msgBuf, "resolveDnsEntryToIp:::ERROR:getaddrinfo: %s", gai_strerror(rv));
		logMsg(OMS_ERROR, msgBuf);
		
		//DOTO: caller to this method should call in future to freeDnsInfo(dnsRes) or safe_free(dnsRes)...
		return (DomainResolutions *)0;
	}

	format = "resolveDnsEntryToIp:::Extracting regular domain (not UDomain) IPs..";
	logMsg(OMS_DEBUG, format);
	
	// loop through all the results and add each to the list
	for(p = servinfo; p != NULL; p = p->ai_next)
	{
		h = (struct sockaddr_in *) p->ai_addr;
		dnsRes->ipList[dnsRes->ipCount++] = copystring(inet_ntoa(h->sin_addr));

		format = "resolveDnsEntryToIp:::IP #[%d] is [%s]";
		sprintf(msgBuf, format, dnsRes->ipCount, dnsRes->ipList[dnsRes->ipCount - 1]);
		logMsg(OMS_DEBUG, msgBuf);
	}

	logMsg(OMS_VERBOSE, "resolveDnsEntryToIp:::Calling safe_free()");
	freeaddrinfo(servinfo); // all done with this structure

	return dnsRes;
}

void freeDnsInfo(DomainResolutions *dnsRes)
{
	/* free all existing IPs strings from memory */
	for (int i = 0; i < dnsRes->ipCount; i++)
	{
		safe_free(dnsRes->ipList[i]);
	}
	safe_free(dnsRes);
}

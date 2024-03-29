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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <libgen.h>

#include <errno.h>

#include "comms.h"
#include "oms_messages.h"
#include "oms_utils.h"
#include "dhcp_event.h"
#include "mud_manager.h"

void buildDhcpEventContext(char *logMsgBuf, char *action, DhcpEvent *dhcpEvent)
{
	sprintf(logMsgBuf, "%s Device Action: IP: %s, MAC: %s", action, dhcpEvent->ipAddress, dhcpEvent->macAddress);
}

/*
 * This will create a filesystem based storage location based on the mudURL argument
 * The fileName will be pulled off the end of the URL and concatinated with the default path
 *
 * This allocates storage so the caller is responsible for freeing memory for returned string when done
 */
char *createStorageLocation(char *mudURL)
{
	char *fileName;
	char *fullPath;

	if (!mudURL)
		return NULL;

	if ((fileName = basename(mudURL)) == NULL)
		return NULL;
//TODO: in this safe_malloc, it maybe should be "strlen (mudFileDataDirectory) + 1"
//	because mudFileDataDirectory will not surely end with "/".
//	and if it is wnding with "/", then why we sprintf a format with another '/'?
//	this code looks like a possible bug  
	if ((fullPath = safe_malloc(strlen (mudFileDataDirectory) + strlen(fileName) + 1)) == NULL)
		return NULL;

	sprintf(fullPath, "%s/%s", mudFileDataDirectory, fileName);

	return fullPath; //TODO: free char* after end of use!
}

char *createSigUrlFromMudUrl(char *mudFileURL)
{
	if (!mudFileURL)
		return NULL;

	return replaceExtension(mudFileURL, MUD_FILE_SIGNATURE_EXTENSION);

}

void doDhcpLegacyAction(DhcpEvent *dhcpEvent)
{
	logMsg(OMS_INFO, "doDhcpLegacyAction::: START.END.");
}

int validateMudFileWithSig(DhcpEvent *dhcpEvent)
{
	int validSig = -1; /* Indicates invalid signature. 0 = valid sig, non-zero is specific signature validation error */

	logMsg(OMS_DEBUG, "IN ****NEW**** validateMudFileWithSig()");

	validSig = verifyCmsSignature(dhcpEvent->mudFileStorageLocation, dhcpEvent->mudSigFileStorageLocation);

	return validSig;
}

const char* getDhcpEventText(DHCP_ACTIONS actionClass)
{
	switch (actionClass)
	{
		case NEW: return "NEW";
		case OLD: return "OLD";
		case DEL: return "DEL";
		default: return "NONE";
	}
}

DHCP_ACTIONS getDhcpEventActionClass(char *dhcpAction)
{
	DHCP_ACTIONS actionClass = NONE;

	if (dhcpAction) {
		if (!strcmp(dhcpAction, "NEW")) {
			actionClass = NEW;
		} else if (!strcmp(dhcpAction, "OLD")) {
			actionClass = OLD;
		} else if (!strcmp(dhcpAction, "DEL")) {
			actionClass = DEL;
		}
	} else {
		actionClass = NONE;
	}

	return actionClass;
}

int processDhcpEventFromLog(char *logMessage, DhcpEvent *dhcpEvent)
{
	/*
	 * Format: Fields are PIPE delimited! This matches up to the "detect_new_devices.sh" script
			Field1: Date
			Field2: Action [NEW|OLD|DEL]
			Field3: Lan device where activated
			Field 4: DHCP options flag - info only
			Field 5: DHCP flags provided for fingerprinting or "-" if not available
			Field 6: MUD flag - info only
			Field 7: MUD url or "-" if not available
			Field 8: DHCP Vendor Class (Option 43)
			Field9: MAC Address
			Field10: IP Address provided by DHCP server
			Field11: Host name *IF* Available
	 */

	char *array[20]; /* really should be the count of spaces in the logMessage+1 */
	int i=0;
	char *tmpStr, *curToken;
	int retval = 1;

	logMsg(OMS_DEBUG, "processDhcpEventFromLog::: START");

	if (logMessage) {
		tmpStr = copystring(logMessage);

		curToken = strtok(tmpStr, "|\t\n\r");
		while (curToken != NULL)
		{
			array[i++] = copystring(curToken);
			curToken = strtok(NULL, "|\t\n\r");
		}

		logMsg(OMS_VERBOSE,"processDhcpEventFromLog:::Calling safe_free()");
		safe_free(tmpStr);
		logMsg(OMS_VERBOSE,"processDhcpEventFromLog:::Called safe_free()");
		
		dhcpEvent->date = array[0];
		dhcpEvent->action = getDhcpEventActionClass(array[1]);
		dhcpEvent->lanDevice = array[2];
		dhcpEvent->dhcpRequestFlags = array[4];
		dhcpEvent->dhcpVendor = array[7];
		dhcpEvent->macAddress = array[8];
		dhcpEvent->ipAddress = array[9];
		dhcpEvent->hostName = array[10];

		/* If the MUD URL is one char long, it's assumed to be invalid */
		dhcpEvent->mudFileURL = NULL;
		if ((array[6] != NULL) && (strlen(array[6]) > 1)) {
			dhcpEvent->mudFileURL = array[6];
		}

		char msgBuf[1024] = {0};
		char *format = "processDhcpEventFromLog:::date[%s],lanDevice[%s],dhcpVendor[%s],MAC[%s],IP[%s],hostname[%s]";
		sprintf(msgBuf, format, dhcpEvent->date, dhcpEvent->lanDevice,
			dhcpEvent->dhcpVendor, dhcpEvent->macAddress, dhcpEvent->ipAddress, dhcpEvent->hostName);
		logMsg(OMS_INFO, msgBuf);
	}
	else
	{
		retval = 0; //error process log message line
	}

	logMsg(OMS_DEBUG, "processDhcpEventFromLog::: END");
	return retval;
}

void clearDhcpEventRecord(DhcpEvent *dhcpEvent)
{
	logMsg(OMS_VERBOSE, "clearDhcpEventRecord::: START. Calling safe_free()");

	dhcpEvent->action = NONE;

	safe_free(dhcpEvent->date);
	safe_free(dhcpEvent->macAddress);
	safe_free(dhcpEvent->ipAddress);
	safe_free(dhcpEvent->hostName);
	safe_free(dhcpEvent->dhcpRequestFlags);
	safe_free(dhcpEvent->dhcpVendor);
	safe_free(dhcpEvent->mudFileURL);
	safe_free(dhcpEvent->mudSigURL);
	safe_free(dhcpEvent->mudFileStorageLocation);
	safe_free(dhcpEvent->mudSigFileStorageLocation);

	dhcpEvent->date = NULL;
	dhcpEvent->macAddress = NULL;
	dhcpEvent->ipAddress = NULL;
	dhcpEvent->hostName = NULL;
	dhcpEvent->dhcpRequestFlags = NULL;
	dhcpEvent->dhcpVendor = NULL;
	dhcpEvent->mudFileURL = NULL;
	dhcpEvent->mudSigURL = NULL;
	dhcpEvent->mudFileStorageLocation = NULL;
	dhcpEvent->mudSigFileStorageLocation = NULL;

	logMsg(OMS_VERBOSE, "clearDhcpEventRecord::: END. After safe_free()");
}

DhcpEvent *cloneDhcpEvent(const DhcpEvent *originalDhcpEvent)
{
	logMsg(OMS_DEBUG, "cloneDhcpEvent::: START");

	DhcpEvent *dhcpEvent = (DhcpEvent *)safe_malloc(sizeof(DhcpEvent));

	dhcpEvent->action = originalDhcpEvent->action;
	dhcpEvent->date = copystring(originalDhcpEvent->date);
	dhcpEvent->macAddress = copystring(originalDhcpEvent->macAddress);
	dhcpEvent->ipAddress = copystring(originalDhcpEvent->ipAddress);
	dhcpEvent->hostName = copystring(originalDhcpEvent->hostName);
	dhcpEvent->dhcpRequestFlags = copystring(originalDhcpEvent->dhcpRequestFlags);
	dhcpEvent->dhcpVendor = copystring(originalDhcpEvent->dhcpVendor);
	if(originalDhcpEvent->mudFileURL)
	{
		dhcpEvent->mudFileURL = copystring(originalDhcpEvent->mudFileURL);
	}
	if(originalDhcpEvent->mudSigURL)
	{
		dhcpEvent->mudSigURL = copystring(originalDhcpEvent->mudSigURL);
	}
	if(originalDhcpEvent->mudFileStorageLocation)
	{
		dhcpEvent->mudFileStorageLocation = copystring(originalDhcpEvent->mudFileStorageLocation);
	}
	if(originalDhcpEvent->mudSigFileStorageLocation)
	{
		dhcpEvent->mudSigFileStorageLocation = copystring(originalDhcpEvent->mudSigFileStorageLocation);
	}
	dhcpEvent->lanDevice = copystring(originalDhcpEvent->lanDevice);

	logMsg(OMS_DEBUG, "cloneDhcpEvent::: END. returning cloned dhcpEvent..");

	return dhcpEvent; //DOTO: caller need to call clearDhcpEventRecord(dhcpEvent) on this returned object
}

#include<stdio.h>
#include<string.h>
#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>
#include <stdlib.h>

#include "udomains_manager.h"
#include "oms_utils.h"
#include "oms_messages.h"


#define MAXLINE 1024

extern int parseMudAndExecuteRules(DhcpEvent *dhcpEvent);

DomainResolutions *_domainsArr[20];
int _idx = 0;

pthread_t _tidManager;


int wasStarted() { return _idx > 1; }

int system_with_output(char *command, char outputLines[15][16], int *numOfLines)
{
	int i = 0;
	FILE *fp;
	char line[1035] = { 0 };
	char msgBuf[1024] = {0};
	char *format;

	sprintf(msgBuf, "system_with_output::: cmd to run is [%s]", command);
	logMsg(OMS_VERBOSE, msgBuf);

	// Open the command for reading. 
	fp = popen(command, "r");
	if (fp == NULL)
	{
		logMsg(OMS_ERROR, "system_with_output: Failed to rum cmd!!!");
		return 1;
	}

	logMsg(OMS_VERBOSE, "system_with_output: cmd ran successfully.Output:");

	format = "Line [%d]:::[%s]";
	// Read the output line at a time - and output it.
	while (fgets(line, sizeof(line), fp) != NULL)
	{
		char *lineWithoutNewLineChar = strtok(line, "\n");
		strcpy(outputLines[i++], lineWithoutNewLineChar);

		sprintf(msgBuf, format, i, lineWithoutNewLineChar);
		logMsg(OMS_VERBOSE, msgBuf);
	}
	*numOfLines = i;

	//close
	pclose(fp);

	return 0;
}

int resolveDomainAddresses(char *domainName, char *dnsServer, char *newIpList[], int *ncount)
{
	int err = 0;
	char execBuf[1024] = { 0 };
	char outputLines[15][16] = { 0 };

	logMsg(OMS_VERBOSE, "resolveDomainAddresses::: START");
	
	snprintf(execBuf, 1024, "nslookup %s %s | awk '/^Address .: / { print $3 }' | grep '\\.'",
		domainName,
		(dnsServer? dnsServer : ""));

	if((err = system_with_output(execBuf, outputLines, ncount)) != 0)
		return err;

	for (int i = 0; i < *ncount; i++)
	{
		newIpList[i] = safe_malloc(16 * sizeof(char));//DOTO: free later when no more in use!
		strcpy(newIpList[i], outputLines[i]);
	}

	logMsg(OMS_VERBOSE, "resolveDomainAddresses::: END");

	return 0;
}

int isDomainResolutionChanged(char *ipList[15], int ipCount, char *newIpList[15], int ncount)
{
	int resChanged = 0;
	int ipFound = 0;
	char msgBuf[1024] = {0};
	char *format;

	logMsg(OMS_VERBOSE, "isDomainResolutionChanged::: START");
	if (ipCount != ncount)
	{
		format = "isDomainResolutionChanged::: TRUE!!::oldIpCount[%d],newIpCount[%d]";
		sprintf(msgBuf, format, ipCount, ncount);
		logMsg(OMS_INFO, msgBuf);
		resChanged = 1;
		goto END;
	}

	//Assuming all IPs in old array are unique (DNS response should return unique ip in each answer).
	//if not, i must also do the same check from the new array to the old array
	for (int i = 0; i < ipCount; i++)
	{
		ipFound = 0;
		for (int j = 0; j < ncount; j++)
		{
			if (strcmp(ipList[i], newIpList[j]) == 0)
			{
				ipFound = 1;
				break;
			}
		}
		if (!ipFound)
		{
			format = "isDomainResolutionChanged::: TRUE!!::oldIp[%s] is not relevant anymore";
			sprintf(msgBuf, format, ipList[i]);
			logMsg(OMS_INFO, msgBuf);

			resChanged = 1;
			break;
		}
	}

END:	sprintf(msgBuf, "isDomainResolutionChanged::: END. resChanged=[%s]", (resChanged>0?"TRUE":"FALSE"));
	logMsg(OMS_VERBOSE, msgBuf);

	return resChanged;
}

void updateDomainWithNewAddresses(DomainResolutions *dnsRes, char *newIpList[], int ncount)
{
	logMsg(OMS_INFO, "updateDomainWithNewAddresses:::Calling safe_free()");
	/* free all existing IPs strings from memory */
	for (int i = 0; i < dnsRes->ipCount; i++)
	{
		safe_free(dnsRes->ipList[i]);
	}
	logMsg(OMS_INFO, "updateDomainWithNewAddresses:::After calling safe_free()");

	/* update */
	logMsg(OMS_INFO, "updateDomainWithNewAddresses::: Updating ipList...");
	/** first, set the new size of the ipList **/	
	dnsRes->ipCount = ncount;

	/** then copy all new IPs to array **/
	for (int i = 0; i < dnsRes->ipCount; i++)
	{
		dnsRes->ipList[i] = newIpList[i]; // newIpList[i] was previously allocated dynamically so no problem
	}
	
	logMsg(OMS_INFO, "updateDomainWithNewAddresses::: END");
}

void handleDomain(DomainResolutions *dnsRes)
{
	char *newIpList[15];
	int ncount, err, resChanged = 0;
	char msgBuf[1024] = {0};
	char *format;

	/* Lock dnsRes since maybe we will update IP Addresses and we want it locked throughout update process */ 
	dnsRes->isLocked = 1;

	format = "handleDomain::: Locked UDomain::Company[%s],domainName[%s],dnsServer[%s]";
	sprintf(msgBuf, format, dnsRes->company, dnsRes->domainName, dnsRes->dnsServer);
	logMsg(OMS_VERBOSE, msgBuf);

	if((err = resolveDomainAddresses(dnsRes->domainName, dnsRes->dnsServer, newIpList, &ncount)) == 0)
	{
		resChanged = isDomainResolutionChanged(dnsRes->ipList, dnsRes->ipCount, newIpList, ncount);
		if (resChanged)
		{
			format = "handleDomain::: ResChange for UDomain::Company[%s],domainName[%s],dnsServer[%s]";
			sprintf(msgBuf, format, dnsRes->company, dnsRes->domainName, dnsRes->dnsServer);
			logMsg(OMS_INFO, msgBuf);

			updateDomainWithNewAddresses(dnsRes, newIpList, ncount);
		}
		else
		{ /* Resolution not changed, IPs stay the same --> free the unused strings of newIpList[] */
			logMsg(OMS_VERBOSE, "handleDomain:::Calling safe_free()");
			for(int i=0;i<ncount;i++)
				safe_free(newIpList[i]);
			logMsg(OMS_VERBOSE, "handleDomain:::End calling safe_free()");
		}
	}
	else
	{
		format = "handleDomain:::ERROR:Cannot resolve UDomain:Company[%s],domainName[%s],dnsServer[%s]";
		sprintf(msgBuf, format, dnsRes->company, dnsRes->domainName, dnsRes->dnsServer);
		logMsg(OMS_ERROR, msgBuf);
	}

	dnsRes->isLocked = 0;

	format = "DomainResolutionChanged: Unlocked UDomain::Company[%s],domainName[%s],dnsServer[%s]";
	sprintf(msgBuf, format, dnsRes->company, dnsRes->domainName, dnsRes->dnsServer);
	logMsg(OMS_VERBOSE, msgBuf);

	if(resChanged)
	{ /* Remove all relevant devices rules and add them again with all new IP Addresses of this unique domain */
		format = "DomainResolutionChanged: Updating [%d] relevant devices with new IP rules!";
		sprintf(msgBuf, format, dnsRes->deviceCount);
		logMsg(OMS_INFO, msgBuf);

		for(int i=0;i < dnsRes->deviceCount;i++)
		{
			format = "DomainResolutionChanged: Updating device #[%d] from total #[%d] relevant devices";
			sprintf(msgBuf, format, i+1, dnsRes->deviceCount);
			logMsg(OMS_INFO, msgBuf);

			parseMudAndExecuteRules(dnsRes->deviceList[i]);//TODO:Uncomment!
		}
	}
}

void *startResolveUniqueDomains(void *param)
{
	int i;
	
	logMsg(OMS_INFO, "startResolveUniqueDomains::: Thread started running!");

	while (1)
	{
		//Dont block context switches, let the process sleep for some time
		sleep(3);
		logMsg(OMS_VERBOSE, "startResolveUniqueDomains::: waken-up!");
		for (i = 0; i < _idx; i++)
		{
			handleDomain(_domainsArr[i]);
		}		
		logMsg(OMS_VERBOSE, "startResolveUniqueDomains::: going to sleep...");
	}
}

void addDomainToFollow(DomainResolutions *dnsRes)
{
	char msgBuf[1024] = {0};
	char *format = "addDomainToFollow::: START. Company[%s],domainName[%s],dnsServer[%s]";
	sprintf(msgBuf, format, dnsRes->company, dnsRes->domainName, dnsRes->dnsServer);
	logMsg(OMS_INFO, msgBuf);

	dnsRes->isLocked = 0;
	dnsRes->ipCount = 0;
	dnsRes->deviceCount = 0;
	_domainsArr[_idx++] = dnsRes;
	if (wasStarted()) return;

	logMsg(OMS_INFO, "startResolveUniqueDomains() thread is starting..");
	pthread_create(&_tidManager, NULL, &startResolveUniqueDomains, NULL);
	logMsg(OMS_INFO, "addDomainToFollow::: END");
}

DomainResolutions *getDomainResolution(const char *domainName, const char *company)
{
	DomainResolutions *retval = (DomainResolutions *)0;
	char msgBuf[1024] = {0};
	char *format = "getDomainResolution::: START. Trying to retrieve using: domainName[%s], Comapny[%s]";
	sprintf(msgBuf, format, domainName, company);
	logMsg(OMS_DEBUG, msgBuf);

	for(int i=0;i<_idx;i++)
	{
		if(domainName)
		{
			if(strcmp(_domainsArr[i]->domainName, domainName) == 0)
			{
				format = "getDomainResolution:::END. Found by domainName!";
				retval = _domainsArr[i];
				goto END;
			}
		}
		if(company)
		{
			if(strcmp(_domainsArr[i]->company, company) == 0)
			{
				format = "getDomainResolution:::END. Found by company!";
				retval = _domainsArr[i];
				goto END;
			}
		}
	}
	
	format = "getDomainResolution::: END. Not Found!!";
	
END:	logMsg(OMS_DEBUG, format);
	return retval;
}

DomainResolutions *getMostSuitableDomainResolution(const char *company)
{
	logMsg(OMS_DEBUG, "getMostSuitableDomainResolution::: START");
	
	DomainResolutions *retval = getDomainResolution(NULL, company);

	if(!retval && _idx > 0)
	{ /* Manufacturer decided to use default iotica and not doing its own subdomains management */
		retval = _domainsArr[0];
	}

	char msgBuf[1024] = {0};
	char *format = "getMostSuitableDomainResolution:::END. Found dnsRes for company[%s]? [%s%s]";
	sprintf(msgBuf, format, company, (retval?"YES:":"NO"), (retval?retval->domainName:""));
	logMsg(OMS_INFO, msgBuf);
	
	return retval;
}

/* Company is the text is the MUD File url that resides between https:// and the 1st slash afterwards.
** In the example of https://avrahamshalev.com/mudfiles/device.json, Company is avrahamshalev.com.
** Company is the same as "Host" header value in HTTP GET Packets 
*/ 
char *getCompanyFromUrl(const char* url)
{
	char msgBuf[1024] = {0};
	sprintf(msgBuf, "getCompanyFromUrl::: START. searching in url[%s]", url);
	logMsg(OMS_DEBUG, msgBuf);

	char *company = getTextBetween(url, "https://", "/");
	if(!company)
	{
		company = getTextBetween(url, "http://", "/");
	}
	sprintf(msgBuf, "getCompanyFromUrl::: END. For url[%s], return value: Company[%s]", url, company);
	logMsg(OMS_DEBUG, msgBuf);

	return company;//DOTO: free this var after end of use!
}

void linkDeviceToItsCompany(DhcpEvent *dhcpEvent)
{
	char *format;
	
	logMsg(OMS_INFO, "linkDeviceToItsCompany::: START");

	char *company = getCompanyFromUrl(dhcpEvent->mudFileURL);
	DomainResolutions *dnsRes = getMostSuitableDomainResolution(company);
	
	logMsg(OMS_INFO, "linkDeviceToItsCompany:::Calling safe_free()");
	safe_free(company);

	if(!dnsRes)
	{
		format = "linkDeviceToItsCompany:::CRITIC ERROR:No unique domains at all! nothing to link to!!!";
		logMsg(OMS_CRIT, format);
		return;
	}

	dnsRes->deviceList[dnsRes->deviceCount++] = cloneDhcpEvent(dhcpEvent);

	logMsg(OMS_INFO, "linkDeviceToItsCompany::: END");
}

int getDeviceEntryFromDomainResolution(DomainResolutions *dnsRes, DhcpEvent *dhcpEvent)
{
	char *format;

	logMsg(OMS_INFO, "getDeviceEntryFromDomainResolution::: START");

	for(int i=0; i< dnsRes->deviceCount;i++)
	{
		if(strcmp(dnsRes->deviceList[i]->ipAddress, dhcpEvent->ipAddress) == 0)			
			if(strcmp(dnsRes->deviceList[i]->macAddress, dhcpEvent->macAddress) == 0)
			{
				format = "getDeviceEntryFromDomainResolution::: Successfully Found Device Entry!";
				logMsg(OMS_INFO, format);
				return i; /*if IP and MAC are equal, this is the device!! */
			}
	}

	format = "getDeviceEntryFromDomainResolution::: END. Can not find Device Entry";
	logMsg(OMS_INFO, format);
	return -1; /* device not found */
}

void unlinkDeviceFromItsCompany(DhcpEvent *dhcpEvent)
{
	char *format;
	
	logMsg(OMS_INFO, "unlinkDeviceFromItsCompany::: START");

	char *company = getCompanyFromUrl(dhcpEvent->mudFileURL);
	DomainResolutions *dnsRes = getMostSuitableDomainResolution(company);
	
	logMsg(OMS_VERBOSE, "unlinkDeviceToItsCompany:::Calling safe_free()");
	safe_free(company);
	
	if(!dnsRes)
	{
		logMsg(OMS_INFO, "unlinkDeviceFromItsCompany::: END. Device was not linked to a unique domain or company");
		return;
	}

	int i = getDeviceEntryFromDomainResolution(dnsRes, dhcpEvent);
	if(i<0)
		{
			format = "unlinkDeviceFromItsCompany:::END. Device Was not found in the linked deviceList[]";
			logMsg(OMS_INFO, format);
			return;
		}

	clearDhcpEventRecord(dnsRes->deviceList[i]);
	dnsRes->deviceList[i] = (DhcpEvent *)0;
	dnsRes->deviceCount--;

	format = "unlinkDeviceFromItsCompany:::END. Device is now unlinked from its unique domain or company";
	logMsg(OMS_INFO, format);
	return;
}

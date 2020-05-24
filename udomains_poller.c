#include<stdio.h>
#include<string.h>
#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>
#include <sys/select.h>

#include "oms_messages.h"
#include "oms_utils.h"
#include "comms.h"
#include "udomains_manager.h"

pthread_t _tidPoller;
FD _udomains_fd;

int pollUdomainsFile(char *line, int maxLineLength, FD filed)
{
	fd_set rfds;
	struct timeval tv;
	int retval;
	int validData = 0; // return that no valid data seen in line until processing shows there is good data
	int hhh = 0;

	FD_ZERO(&rfds);
	FD_SET(filed, &rfds);

	/* Wait up to two seconds. */
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	retval = select(filed + 1, &rfds, NULL, NULL, &tv);

	if (retval == -1) {
		perror("select()");
		logMsg(OMS_CRIT, "pollUdomainsFile:Cannot poll udomains file!!!");
		exit(EXIT_FAILURE);
	}
	else if (retval) {
		if (FD_ISSET(filed, &rfds)) /* is true so input is available now. */
		{
			if ((hhh = readLine(line, MAXLINE, filed)) > 1)
			{
				char msgBuf[1024] = {0};
				char *format = "pollUdomainsFile:got new udomain from udomains file::line[%s]";
				sprintf(msgBuf, format, line);
				logMsg(OMS_INFO, msgBuf);
				validData = 1;
			}
		}
	}

	return validData;
}

void processUdomainFromLog(char *udomainLineToParse, DomainResolutions *dnsRes)
{
	char *arr[3];
	int i = 0;
	char *tmpStr, *curToken;

	logMsg(OMS_INFO, "processUdomainFromLog::: START");

	arr[2] = NULL;
	if (udomainLineToParse)
	{
		tmpStr = copystring(udomainLineToParse);

		curToken = strtok(tmpStr, "|\t\n\r");
		while (curToken != NULL && i<3) {
			arr[i++] = copystring(curToken);
			curToken = strtok(NULL, "|\t\n\r");
		}
		safe_free(tmpStr);

		dnsRes->company = arr[0];
		dnsRes->domainName = arr[1];
		dnsRes->dnsServer = arr[2];

		char msgBuf[1024] = {0};
		char *format = "processUdomainFromLog: Parsed :: Company[%s],domainName[%s],dnsServer[%s]";
		sprintf(msgBuf, format, dnsRes->company, dnsRes->domainName, dnsRes->dnsServer);
		logMsg(OMS_INFO, msgBuf);
	}
}

void *startPollUniqueDomainsFile(void *param)
{
	int hhh;
	char udomainLine[MAXLINE] = {0};

	logMsg(OMS_INFO, "startPollUniqueDomainsFile::: Thread started running!");

	while (1)
	{
		logMsg(OMS_VERBOSE, "startPollUniqueDomainsFile::: waken-up!");

		if ((hhh = pollUdomainsFile(udomainLine, MAXLINE, _udomains_fd)) != 0)
		{
			DomainResolutions *dnsRes = (DomainResolutions *)safe_malloc(sizeof(DomainResolutions));
			processUdomainFromLog(udomainLine, dnsRes);
			addDomainToFollow(dnsRes);
		}

		logMsg(OMS_VERBOSE, "startPollUniqueDomainsFile::: going to sleep...");
		//Dont block context switches, let the process sleep for some time
		sleep(10);
	}
}

int startPollingUdomainsInDifferentThread(FD udomains)
{
	int errCode = 0;

	_udomains_fd = udomains;

	logMsg(OMS_INFO, "startPollingUdomainsInDifferentThread::: START. startPollUniqueDomainsFile() thread is starting..");

	errCode = pthread_create(&_tidPoller, NULL, &startPollUniqueDomainsFile, NULL);
	if (errCode != 0)
	{
		printf("startPollingUdomainsInDifferentThread:::OSMUD could not run the thread that polls udomains! QUITTING!");
	}
	
	logMsg(OMS_INFO, "startPollingUdomainsInDifferentThread::: END");
	return errCode;
}

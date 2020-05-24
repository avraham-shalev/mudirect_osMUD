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
#include <sys/select.h>

#include <errno.h>

#include "comms.h"
#include "oms_messages.h"
#include "oms_utils.h"
#include "dhcp_event.h"
#include "mud_manager.h"
#include "udomains_poller.h"
#include "version.h"

/* Default locations for osMUD resources based on OpenWRT */
#define MUD_FILE_DIRECTORY "/var/osmud/mudfiles"
#define DHCP_EVENT_FILE "/var/osmud/dhcpmasq.txt"
#define PID_FILE "/var/run/osmud.pid"
#define OSMUD_LOG_FILE "/var/osmud/osmud.log"
#define OSMUD_UDOMAINS_FILE "/etc/osmud/udomains.txt"

char *dnsWhiteListFile = (char *)0;
char *mudFileDataDirectory = (char *)0;
char *dhcpEventFile = (char *)0;
char *osmudPidFile = (char *)0;
char *osMudLogFile = (char *)0;
char *uniqueDomainsFile = (char *)0;

int noFailOnMudValidation = 0;

int heartBeatCycle = 0; /* how many polling cycles have passed in this interval period*/
int heartBeatLogInterval = 720; /* Every x cycles, trigger the heartbeat log - 1 hour */
int sleepTimeout = 5; /* how log to sleep between polling the event file - in seconds */

int pollDhcpFile(char *line, int maxLineLength, FD filed)
{
    fd_set rfds;
    struct timeval tv;
    int retval;
    int validData = 0; // Begin with returning that there was no valid data see on the line until processing shows there is good data
	int hhh = 0;

	FD_ZERO(&rfds);
	FD_SET(filed, &rfds);

	/* Wait up to three seconds. */
	tv.tv_sec = 3;
	tv.tv_usec = 0;

	retval = select(filed+1, &rfds, NULL, NULL, &tv);

	if (retval == -1) {
		perror("select()");
		exit(EXIT_FAILURE);
	}
	else if (retval) {
		if (FD_ISSET(filed, &rfds)) /* is true so input is available now. */
		{
			if ((hhh = readLine(line, MAXLINE, filed)) > 1)
			{
				logMsg(OMS_DEBUG, "Data read on device");
				logMsg(OMS_DEBUG, line);
				validData = 1;
			}
		}
	}

	return validData;
}

void dumpStatsToLog()
{
	char msgBuf[1024] = {0};
	buildDhcpEventsLogMsg(msgBuf, 1024);
	logMsg(OMS_INFO, msgBuf);
}

void doProcessLoop(FD filed)
{
	char dhcpEventLine[MAXLINE];
	DhcpEvent dhcpEvent;
	dhcpEvent.action = NONE;
	dhcpEvent.date = NULL;
	dhcpEvent.macAddress = NULL;
	dhcpEvent.ipAddress = NULL;
	dhcpEvent.hostName = NULL;
	dhcpEvent.dhcpRequestFlags = NULL;
	dhcpEvent.dhcpVendor = NULL;
	dhcpEvent.mudFileURL = NULL;
	dhcpEvent.mudSigURL = NULL;
	dhcpEvent.mudFileStorageLocation = NULL;
	dhcpEvent.mudSigFileStorageLocation = NULL;

	while (1)
	{
		//Dont block context switches, let the process sleep for some time
		sleep(sleepTimeout);
		
		logMsg(OMS_VERBOSE, "doProcessLoop:::waken-up!");
		int hhh;
		if ((hhh = pollDhcpFile(dhcpEventLine, MAXLINE, filed))) {
			logMsg(OMS_DEBUG, "doProcessLoop:::New info received from dhcpmasq file");
			if (processDhcpEventFromLog(dhcpEventLine, &dhcpEvent))
			{
				// There is a valid DHCP event to process
				acquireLock();
				logMsg(OMS_DEBUG, "doProcessLoop:::Going to process DHCP Event..Calling executeOpenMudDhcpAction()");
				executeOpenMudDhcpAction(&dhcpEvent);
			}
			else
			{
				logMsg(OMS_DEBUG, "doProcessLoop:::Will not process DHCP event - invalid message format.... sleeping for 5...");
			}
		}
		else
		{
			logMsg(OMS_VERBOSE, "doProcessLoop:::No data read...");
		}

		// Clear variables for next iteration
		logMsg(OMS_VERBOSE, "doProcessLoop:::Calling clearDhcpEventRecord()");

		clearDhcpEventRecord(&dhcpEvent);

		if (heartBeatCycle++ > heartBeatLogInterval) {
			dumpStatsToLog();
			heartBeatCycle = 0;
		}

		logMsg(OMS_VERBOSE, "doProcessLoop::: Going to sleep..");
		releaseLock();
	}
}

void printVersion()
{
	printf("osmud\n");
	printf("    Version: %s\n", build_git_sha);
	printf("    Build Date: %s\n", build_git_time);
}

void printHelp()
{
	printf("osmud -h | <options>\n\n");
	printf("OPTIONS:\n");
	printf("    -d: Run with -d for now to keep the system from forking into a daemon process\n");
	printf("    -k: Keep in foreground -- no debug mode, but don't run as daemon process\n");
	printf("    -x <pidfile>: set PID file -- Normally /var/run/osmud.pid\n");
	printf("    -m <log-level>: Set log level to INFO, DEBUG, WARN, ERROR, CRIT\n");
	printf("    -i: Do not fail processing when the MUD file p7s file does not validate\n");
	printf("    -e <dhcpEventFile>: set the file path and name for DHCP event file\n");
	printf("    -w <dnsWhiteListFile>: set the file path and name for DNS white-list file\n");
	printf("    -b <MUD file storage data directory>: set the directory path for MUD file storage\n");
	printf("    -c <osMUD config file>: set the directory path and file for osMUD startup configuration file\n");
	printf("    -u <osMUD unique domains file>: set the file path and name for Unique Domains file\n");
	printf("    -l <osMUD logfile>: set the osMUD logger path and file for system event logging.\n");
	printf("    -v: display osmud version information and exit\n");

}

void checkForDefaults() {
	if (!dnsWhiteListFile) dnsWhiteListFile = copystring(DNS_FILE_NAME_WITH_PATH);
	if (!mudFileDataDirectory) mudFileDataDirectory = copystring(MUD_FILE_DIRECTORY);
	if (!dhcpEventFile) dhcpEventFile = copystring(DHCP_EVENT_FILE);
	if (!osmudPidFile) osmudPidFile = copystring(PID_FILE);
	if (!osMudLogFile) osMudLogFile = copystring(OSMUD_LOG_FILE);
	if (!uniqueDomainsFile) uniqueDomainsFile = copystring(OSMUD_UDOMAINS_FILE);
}

int writePidFile(pid_t osMudPid) {
	FILE *fp= NULL;
	int retval = 0;
	fp = fopen_with_path(osmudPidFile, "w");

	if (fp != NULL)
        {
            fprintf(fp, "%d\n", osMudPid);

            fflush(fp);
            fclose(fp);
        }
        else
	{
            logMsg(OMS_CRIT, "Could not write to PID file.");
            retval = 1;
	}

	return retval;
}

void logInitialSettings()
{
	char msgBuf[1024] = {0};
	logMsg(OMS_INFO, "  Starting OSMUD controlling with initial settings:");

	sprintf(msgBuf, "    PID FILE: %s", osmudPidFile);
	logMsg(OMS_INFO, msgBuf);

	sprintf(msgBuf, "    DHCP event file: %s", dhcpEventFile);
	logMsg(OMS_INFO, msgBuf);

	sprintf(msgBuf, "    DNS white-list file: %s", dnsWhiteListFile);
	logMsg(OMS_INFO, msgBuf);

	sprintf(msgBuf, "    MUD file storage directory: %s", mudFileDataDirectory);
	logMsg(OMS_INFO, msgBuf);

	sprintf(msgBuf, "    osMUD logger path and file: %s", osMudLogFile);
	logMsg(OMS_INFO, msgBuf);
}

int main(int argc, char* argv[])
{
	FILE *logger= NULL;
	pid_t process_id = 0;
	pid_t sid = 0;

    int opt;
    int debugMode = 0;
    int foregroundMode = 0;
    char *osLogLevel = NULL;

    while ((opt = getopt(argc, argv, "vidhkx:e:w:b:c:l:m:u:")) != -1) {
        switch (opt) {
        case 'd':       debugMode = 1;
        				break;
        case 'i':       noFailOnMudValidation = 1;
        				break;
        case 'h': printHelp();
        				exit(EXIT_FAILURE);
        				break;
        case 'v': printVersion();
        				exit(EXIT_FAILURE);
        				break;
        case 'k': 		foregroundMode = 1;
        				break;
        case 'x': 		osmudPidFile = copystring(optarg);
						break;
        case 'e': 		dhcpEventFile = copystring(optarg);
						break;
		case 'w': 		dnsWhiteListFile = copystring(optarg);
						break;
		case 'b': 		mudFileDataDirectory = copystring(optarg);
						break;
		case 'l': 		osMudLogFile = copystring(optarg);
						break;
		case 'm':		osLogLevel = copystring(optarg);
						break;
		case 'u':		uniqueDomainsFile = copystring(optarg);
						break;
        default:
            printHelp(); /* If you find an unknown option, do not start up */
            exit(EXIT_FAILURE);
        }
    }

    checkForDefaults();

	// Open a log file in write mode.
    if (!(logger = fopen_with_path(osMudLogFile, "w+"))) {
    	printf("OSMUD could not open the system logger output file. Use the \"-l <log-file-name-with-path>\" option to set the logging to a location with write access.\n");
		return -1;
    }

    if (createMudfileStorage(mudFileDataDirectory) != 0) {
    	printf("OSMUD could not create the MUD file storage location. Use the \"-b <mud-storage-path>\" option to set the MUD storage location to a directory with write access.\n");
		return -1;
    }

    resetDhcpCounters();
	setOmsLogger(logger);
	if (debugMode == 1)
		setLoggingLevel(OMS_DEBUG);
	else
		setLoggingLevel(getLogLevelFromArg(osLogLevel));
	initializeMessageLogging();
	logInitialSettings();

	/* Open the DHCP Event File for read - OSMUD processes one event per line
	 * It is expected that this full path and file exist since this is intended
	 * to be the output of DHCP events
	 */
    FD filed = open(dhcpEventFile, O_RDONLY );
    FD unique_domains_fd = open(uniqueDomainsFile, O_RDONLY );

    if (!(filed > 0)) {
    		printf("OSMUD could not open the DHCP event file: %s - open failed. Use the \"-e <dhcp-event-file-with-path>\" option to set where the DHCP service is writing events.\n", dhcpEventFile);
    		return -1;
    }

    if (!(unique_domains_fd > 0)) {
    		printf("OSMUD could not open the Unique Domains file at [%s] - open failed. Use the \"-u <unique-domains-file-with-path>\" option to set where the app is writing the unique domains to.\n", uniqueDomainsFile);
    		return -1;
    }

    if ((debugMode) || (foregroundMode))
    {
  		printf("Running OSMUD in the foreground... <cntrl-c> to terminate\n");
    }
    else
    {
		// Create child process
		process_id = fork();

		// Indication of fork() failure
		if (process_id < 0)
		{
			printf("fork failed!\n");
			// Return failure in exit status
			exit(1);
		}

		// PARENT PROCESS. Need to kill it.
		if (process_id > 0)
		{
			writePidFile(process_id);
			exit(0);
		}

		//unmask the file mode
		umask(0);

		//set new session
		sid = setsid();
		if (sid < 0)
		{
			// Return failure
			exit(1);
		}

		// Change the current working directory to root.
		chdir("/tmp");
    }

//DOTO: Uncomment these lines!! they were commented by me for debugging!!!!
// Close stdin. stdout and stderr
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	if(startPollingUdomainsInDifferentThread(unique_domains_fd))
		return -1;
	doProcessLoop(filed);

	close(filed);
	fclose(logger);
	return (0);
}


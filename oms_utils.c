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
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>

#include "oms_messages.h"
#include "oms_utils.h"

int _lockInitialized = 0;
pthread_mutex_t _lockObj;

void acquireLock()
{
	if(!_lockInitialized)
	{
		pthread_mutex_init(&_lockObj, NULL);
		_lockInitialized = 1;
	}
	pthread_mutex_lock(&_lockObj);
}

void releaseLock()
{
	if(!_lockInitialized)
	{
		return;
	}
	pthread_mutex_unlock(&_lockObj);
}

char *safe_malloc(unsigned n)
{
	/* this will call malloc and exit with error if malloc returns 0 */
	char *t;

	if (n != 0)
		if ((t = malloc(n)) != 0)
			memset(t, 0, n);
		else
			logOmsMessage(OMS_CRIT, OMS_SUBSYS_GENERAL, OUT_OF_MEMORY);
	else
		t = 0;


	return t;
}

void safe_free(void* p)
{
	if (p != 0)
		free(p);
}

char *copystring(const char *s)
{
	char *st;
	char msgBuf[strlen(s) * 2 + 100];
	memset(msgBuf, 0, strlen(s) * 2 + 100); //zero memory  so for sure the string will end with '\0'
	sprintf(msgBuf, "copystring::: START. Copying string[%s]", s);
	logMsg(OMS_VERBOSE, msgBuf);

	if (!s)
	{
		logMsg(OMS_ERROR, "copystring:::ERROR: END. CAN NOT COPY STRING!!!");
		return 0;
	}

	st = safe_malloc((unsigned)(strlen(s) + 1));
	(void) strcpy(st,s);

	sprintf(msgBuf, "copystring:::END. Copied string[%s] to another string[%s]", s, st);
	logMsg(OMS_VERBOSE, msgBuf);

	return st; //DOTO: caller need to safe_free() this string!
}

/* upper\lower-case is NOT taken into account in strcmpi() */
int strcmpi(const char s1[], const char s2[])
{
/* this routine returns >, ==, or < 0 as s1 is >, ==, or < s2. */

	int diff, i;
	char c1, c2;

	i = 0;
	do
	{
			c1 = islower(s1[i]) ? toupper(s1[i]) : s1[i];
			c2 = islower(s2[i]) ? toupper(s2[i]) : s2[i];
			diff = c1 - c2;
			i++;
	} while (s1[i - 1] && s2[i - 1] && !diff);

	char msgBuf[strlen(s1) + strlen(s2) + 100];
	memset(msgBuf, 0, strlen(s1) + strlen(s2) + 100); //zero memory  so for sure the string will end with '\0'
	sprintf(msgBuf, "strcmpi:::str1[%s], str2[%s], returns: Difference[%d]", s1, s2, diff);
	logMsg(OMS_VERBOSE, msgBuf);

	return diff;
}

char *readFileToString(const char *inputFileName)
{
	FILE *fp;
	struct stat statbuf;
	char *fileContents = (char *)0;
	size_t f;

	char msgBuf[1024] = {0};
	char *format = "readFileToString:::START. Going to read contents of file[%s] if it exists";
	sprintf(msgBuf, format, inputFileName);
	logMsg(OMS_DEBUG, msgBuf);

	if (!inputFileName)
	{
		format = "readFileToString:::ERROR:END. Cannot read file[%s] as string since file does not exist!!!";
		sprintf(msgBuf, format, inputFileName);
		logMsg(OMS_ERROR, msgBuf);
		return (char *)0;

	}

	logMsg(OMS_DEBUG, "readFileToString::: Calling fopen(read) on file");
	if ((fp = fopen(inputFileName, "r")) != 0)
	{
		logMsg(OMS_DEBUG, "readFileToString::: Calling stat() on file");
		if (stat(inputFileName, &statbuf) == 0)
		{
			fileContents = safe_malloc(statbuf.st_size + 1);
			f = fread(fileContents, sizeof(char), statbuf.st_size, fp);
			fileContents[f] = '\0';
			fclose(fp);
		}
	}
	else
	{
		format = "readFileToString:::ERROR:END. Cannot open file[%s] for reading (read file permissions?)";
		sprintf(msgBuf, format, inputFileName);
		logMsg(OMS_ERROR, msgBuf);
		return (char *)0;
	}

	sprintf(msgBuf, "readFileToString::: End. strlen(fileContents)=[%ld]", strlen(fileContents));
	logMsg(OMS_DEBUG, msgBuf);
	return fileContents;//DOTO: free this char* after use!
}

/*
 * This will look for the last "." character in fileUrl and replace
 * afterward with newExtension.
 *
 * Caller is responsible for freeing this memory
 */
char *replaceExtension(char* fileUrl, char *newExtension) {
    char *retstr;
    char *base;
    char *lastdot;

    if (fileUrl == NULL)
         return NULL;

    if (newExtension == NULL)
        return NULL;

    if ((base = safe_malloc(strlen (fileUrl) + 1)) == NULL)
        return NULL;

    if ((retstr = safe_malloc(strlen (fileUrl) + strlen(newExtension) + 1)) == NULL)
        return NULL;

    strcpy (base, fileUrl);
    lastdot = strrchr (base, '.');
    if (lastdot != NULL)
    {
        *lastdot = '\0';
    }

    sprintf(retstr, "%s.%s", base, newExtension);

	logMsg(OMS_VERBOSE, "replaceExtension:::Calling safe_free()");
    safe_free(base);

    return retstr;
}

/*
 * Recursive function that will create a list of directories. It uses stack memory
 * and assumes the path input is memory that can be modified.
 * Returns 0 - successful path creation
 *         1 - something went wrong
 */
int mkdir_path(char *path)
{
	int result = 0;
	char *sep = strrchr(path, '/' );

	if(sep != NULL) {
		*sep = 0;
		if ((result = mkdir_path(path))) {
			/* There was a problem making the path - stop and return error */
			return 1;
		}
		*sep = '/';
	}

	if (*path) {
		if( mkdir(path,0755) && errno != EEXIST ) {
			return 1;
		} else {
			return 0;
		}
	}
	/* else, a null path does not cause an error - it's skipped */

	return 0;
}

/*
 * Attempts to open a file that includes a path. All parts of the path will try to be created
 * If the path cannot be created or the file cannot be opened, null will be returned
 */
FILE *fopen_with_path(char *path, char *mode)
{
    char *sep = strrchr(path, '/' );
    int result = 0;

    if (sep) {
		char *path_t = strdup(path);
		path_t[sep - path] = 0;
		result = mkdir_path(path_t);
		logMsg(OMS_VERBOSE, "fopen_with_path:::Calling safe_free()");
		safe_free(path_t);
    }

    if (!result)
    	return fopen(path, mode);
    else
    	return (FILE *)0;
}

int readLine(char *buffer, int maxLineLength, int fd)
{
    int bytes_read;
    int k = 0;
    int fDone = 0;
    do {
        char t = 0;
        bytes_read = read(fd, &t, 1);

        if (t == '\n') {
            buffer[k]='\0';
            fDone = 1;
        }
        else if (k < maxLineLength) {
            buffer[k++] = t;
        } else {
        		// printf("Line too long...");
        		fDone = 1;
        }
    }
    while ((bytes_read != 0) && (!fDone));

    return k;
}

char *getTextBetween(const char *str, const char *param1, const char *param2)
{
	char *i1;
	size_t len1;
	char *i2;
	size_t mlen;
	char *ret = (char *)0;

	logMsg(OMS_DEBUG, "getTextBetween::: START");

	if(str && param1 && param2)
	{
		i1 = strstr(str, param1);
		if(i1 != NULL)
		{
			len1 = strlen(param1);
			i2 = strstr(i1 + len1, param2);
			if(i2 != NULL)
			{
				/* Found both markers, extract text. */
				 mlen = i2 - (i1 + len1);
				 ret = safe_malloc(mlen + 1);
				if(ret != NULL)
				{
					memcpy(ret, i1 + len1, mlen);
					ret[mlen] = '\0';
				}
			}
		}
	}

	char msgBuf[1024] = {0};
	char *format = "getTextBetween::: Input: str[%s],param1[%s],param2[%s] --> Result[%s]";
	sprintf(msgBuf, format, str, param1, param2, ret);
	logMsg(OMS_INFO, msgBuf);

	
	logMsg(OMS_DEBUG, "getTextBetween::: END");
	return ret;//DOTO: if ret!=NULL caller need to free it by the end of use!!
}

int isFileContainsStr(const char *filePath, const char *str)
{
	logMsg(OMS_DEBUG, "isFileContainsStr:::START");

	char msgBuf[1024] = {0};	
	char *fileContents = readFileToString(filePath);

	if(!fileContents || !str)
	{
		char *format = "isFileContainsStr:::ERROR: Both {fileContents[%s],str[%s]} must not be null! Calling safe_free()";
		sprintf(msgBuf, format, fileContents, str);
		logMsg(OMS_ERROR, msgBuf);
		logMsg(OMS_DEBUG, "isFileContainsStr:::END. After safe_free()");
		safe_free(fileContents);
		return 0;
	}

	int isContains = strstr(fileContents, str) ? 1 : 0;
	
	logMsg(OMS_VERBOSE, "isFileContainsStr:::Calling safe_free()");
	safe_free(fileContents);

	char *format = "isFileContainsStr::: END. is FilePath[%s] contains str[%s]? Answer:[%s]";
	sprintf(msgBuf, format, filePath, str, (isContains?"YES":"NO"));
	logMsg(OMS_DEBUG, msgBuf);

	return isContains; 
}

/* //TODO: escape also '/' '*' and other needed symbols.... */
char *getEscapedStr(const char *strWithCharsToEscape)
{
int len = strlen(strWithCharsToEscape);
        char escaped[1024] = {0};
        int j=0;
        for(int i=0;i<len;i++)
        {
                if(strWithCharsToEscape[i] =='$')
                {
                        escaped[i+j] = '\\';
                        j++;
                }
                escaped[i+j] = strWithCharsToEscape[i];
        }
	char *retval = copystring(escaped);
	return retval; //DOTO: caller need to free this string!!
}

int replaceTextInFile(const char *filePath, const char *oldStr, const char *newStr)
{
	char execBuf[1024] = {0};
	char *format = "sed -i 's/%s/%s/g' %s";

	char *escapedOldStr = getEscapedStr(oldStr);
	char *escapedNewStr = getEscapedStr(newStr);
	sprintf(execBuf, format, escapedOldStr, escapedNewStr, filePath);

	safe_free(escapedOldStr);
	safe_free(escapedNewStr);
	
	char msgBuf[1024] = {0};	
	format = "replaceTextInFile::: START. Running cmd[%s]";
	sprintf(msgBuf, format, execBuf);
	logMsg(OMS_DEBUG, msgBuf);

	system(execBuf);
	
	if(isFileContainsStr(filePath, oldStr))
	{
		format = "replaceTextInFile:::CRITIC ERROR:END. file[%s] contains oldstr[%s] after replacements!!!";
		sprintf(msgBuf, format, filePath, oldStr);
		logMsg(OMS_CRIT, msgBuf);
		return 0;
	}

	format = "replaceTextInFile::: END. Successfully replaced all oldstr[%s] with newStr[%s] in file[%s]";
	sprintf(msgBuf, format, oldStr, newStr, filePath);
	logMsg(OMS_INFO, msgBuf);

	return 1;
}

int deleteLinesThatContainsStrFromFile(const char *filePath, const char *str)
{
	char execBuf[1024] = {0};
	char *format = "sed -i '/%s/d' %s";
	
	char *escapedStr = getEscapedStr(str);
	sprintf(execBuf, format, escapedStr, filePath);

	safe_free(escapedStr);
	
	char msgBuf[1024] = {0};
	format = "deleteLinesThatContainsStrFromFile::: START. Running cmd[%s]";
	sprintf(msgBuf, format, execBuf);
	logMsg(OMS_DEBUG, msgBuf);

	system(execBuf);

	if(isFileContainsStr(filePath, str))
	{
		format = "deleteLinesThatContainsStrFromFile:::CRITIC ERROR: END. file[%s] still contains str[%s]!!";
		sprintf(execBuf, format, filePath, str);
		logMsg(OMS_CRIT, execBuf);
		return 0;
	}

	format = "deleteLinesThatContainsStrFromFile::: END. Successfully deleted all str[%s] from file[%s]";
	sprintf(msgBuf, format, str, filePath);
	logMsg(OMS_DEBUG, msgBuf);

	return 1;
}

/* append line to file. line parameter should not contain '\n' !!! */
int appendLineToFile(const char *filePath, const char *line)
{
	int retval = 1;
	FILE *fp= NULL;

	char msgBuf[1024] = {0};
	char *format = "appendLineToFile::: START. Trying to append line[%s] to file[%s]. Executing fopen(append)..";
	sprintf(msgBuf, format, line, filePath);
	logMsg(OMS_DEBUG, msgBuf);

	fp = fopen (filePath, "a");
	if (fp != NULL)
        {
		logMsg(OMS_VERBOSE, "appendLineToFile:::Executing fprintf(..)");
		fprintf(fp, "%s\n", line);
		logMsg(OMS_VERBOSE, "appendLineToFile:::Executing fflush(..)");
		fflush(fp);
		logMsg(OMS_VERBOSE, "appendLineToFile:::Executing fclose(..)");
		fclose(fp);

		format = "appendLineToFile::: Successfully appended line[%s] to file[%s]";
		sprintf(msgBuf, format, line, filePath);
		logMsg(OMS_DEBUG, msgBuf);
        }
        else
	{
		format = "appendLineToFile:::CRITIC ERROR: Cannot append line[%s] to file[%s]!!!!!!";
		sprintf(msgBuf, format, line, filePath);
		logMsg(OMS_CRIT, msgBuf);
		retval = 0;
	}

		logMsg(OMS_DEBUG, "appendLineToFile::: END");

	return retval;
}

/* Private IP Addresses are 10.X.Y.Z, 172.16.X.Y-172.31.X.Y, 192.168.X.Y */
int isPrivateIP(const char *ip)
{
	int retVal = 0;
	char *octets[2];
	const int MAX_IP_LENGTH = 15;
	char *ipAsStr = safe_malloc(MAX_IP_LENGTH + 1);
	strcpy(ipAsStr, ip);

	octets[0] = strtok(ipAsStr, ".");
	if (!strcmp(octets[0], "10")) // handle IPs 10.X.Y.Z
	{
		retVal = 1;
		goto END;
	}

	octets[1] = strtok(NULL, ".");
	if (!strcmp(octets[0], "192") && !strcmp(octets[1], "168")) //handle IPs 192.168.X.Y
	{
		retVal = 1;
		goto END;
	}
	if (!strcmp(octets[0], "172")) //handle IP range 172.16.X.Y-172.31.X.Y
	{
		int octet2Int = atoi(octets[1]);
		retVal = octet2Int >= 16 && octet2Int <= 31;
		goto END;
	}

END:
	safe_free(ipAsStr);
	return retVal;
}

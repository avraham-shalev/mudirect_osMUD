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

#ifndef _OMS_UTILS
#define _OMS_UTILS

#define MAXLINE 1024

typedef int FD;

void acquireLock();
void releaseLock();

char *safe_malloc(unsigned n);
void safe_free(void *p);
char *copystring(const char *s);
int strcmpi(const char s1[], const char s2[]);
char *replaceExtension(char* fileUrl, char *newExtension);

int mkdir_path(char *path);
FILE *fopen_with_path( char *path, char *mode );
int readLine(char *buffer, int maxLineLength, int fd);
char *readFileToString(const char *inputFileName);
char *getTextBetween(const char *str, const char *param1, const char *param2);
int isFileContainsStr(const char *filePath, const char *str);
int replaceTextInFile(const char *filePath, const char *oldStr, const char *newStr);
int deleteLinesThatContainsStrFromFile(const char *filePath, const char *str);
int appendLineToFile(const char *filePath, const char *line);

#endif

#include "dhcp_event.h"

typedef struct {
	char *domainName;
	char *company;
	char *dnsServer;
	char *ipList[15];
	int ipCount;
	DhcpEvent *deviceList[50];
	int deviceCount;
} DomainResolutions;

void addDomainToFollow(DomainResolutions *dnsRes);
DomainResolutions *getDomainResolution(const char *domainName, const char *company);
DomainResolutions *getMostSuitableDomainResolution(const char *company);
char *getCompanyFromUrl(const char* url);
void linkDeviceToItsCompany(DhcpEvent *dhcpEvent);
void unlinkDeviceFromItsCompany(DhcpEvent *dhcpEvent);

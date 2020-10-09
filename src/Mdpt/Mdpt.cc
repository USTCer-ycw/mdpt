
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include "src/Util/Util.h"

using std::string;


uint64_t current_pkt = 0;

int printPktHeader(PCAP_PKTHEADER *pktHeader)
{
    fprintf(stdout, "cap_time:%u, ", (unsigned int)pktHeader->ts.tv_sec);
    fprintf(stdout, "pkt length:%u, ", pktHeader->len);
    fprintf(stdout, "cap length:%u\n", pktHeader->caplen);
}

void lihui_callback(u_char *argument, const struct pcap_pkthdr *header, const u_char *data)
{
    fprintf(stdout, "cap_time:%u, ", (unsigned int)header->ts.tv_sec);

    u_char* temp = const_cast<u_char*>(data);
    string sip = getSrcIp(temp);
    string dip = getDstIp(temp);
    uint64_t seqnum = getSeqnum(temp);
    u_char* payload = getPayload(temp);
    printf("The %d packet length: %d\n", ++current_pkt, header->len);
    printf("src ip: %s,dst ip: %s\n",    sip.c_str(), dip.c_str());
	printf("The packet sequence number and data: %d, %x\n", seqnum, *payload);
}


int lookupdev()
{
	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	dev = pcap_lookupdev(errbuf);

	if (NULL == dev)
	{
		fprintf(stdout, "error:%s\n", errbuf);
		return (EXIT_FAILURE);
	}
	printf("device:%s\n", dev);
	return (EXIT_SUCCESS);
}

void test()
{
	//open the dumped cap file
    string filename = "haitong_sp.pcap";

    pcap_t* handle = NULL;

    open_pcap_file(&handle,filename.c_str());

    u_char * ptr = (u_char*)handle;
    ptr += 14;

    pcap_loop(handle, -1, (pcap_handler)lihui_callback, (u_char*)handle);

    //read the cap file , and print the every captured packet summary

    //close the handle
    pcap_close(handle);
}



int main(int argc, char *argv[])
{
    fprintf(stdout, "beg time=%d\n", time(0));

	test();

    fprintf(stdout, "end time=%d\n", time(0));
	return (EXIT_SUCCESS);
}


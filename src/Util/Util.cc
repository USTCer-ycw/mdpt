
#include "src/Util/Util.h"

u_char* getPayload(u_char* data)
{
    struct packet_ip* ip = static_cast<packet_ip*>(implicit_cast<void*>(data + SIZE_ETHERNET));
    u_char ipheaderlen = IP_HL(ip) << 2;
    struct packet_tcp* tcp = static_cast<packet_tcp*>(implicit_cast<void*>(data + SIZE_ETHERNET + ipheaderlen));
    u_char tcpheaderlen = TH_OFF(tcp) << 2;
    return data + SIZE_ETHERNET + ipheaderlen + tcpheaderlen;
}

string getSrcIp(u_char* data)
{
    struct packet_ip* ip = static_cast<packet_ip*>(implicit_cast<void*>(data + SIZE_ETHERNET));
    return inet_ntoa(ip->ip_src);
}

string getDstIp(u_char* data)
{
    struct packet_ip* ip = static_cast<packet_ip*>(implicit_cast<void*>(data + SIZE_ETHERNET));
    return inet_ntoa(ip->ip_dst);
}

uint32_t getSeqnum(u_char* data)
{
    struct packet_ip* ip = static_cast<packet_ip*>(implicit_cast<void*>(data + SIZE_ETHERNET));
    u_char ipheaderlen = IP_HL(ip) << 2;
    struct packet_tcp* tcp = static_cast<packet_tcp*>(implicit_cast<void*>(data + SIZE_ETHERNET + ipheaderlen));
    return tcp->th_seq;
}

u_char* getIpPayload(u_char* data)
{

}

u_char* getTcpPayload(u_char* data)
{
    
}


bool setsrcfilter(pcap_t* handle,char* filterIP)
{
    struct bpf_program filter;
    string src = "src";
    string filter_ip = src + filterIP;
    int ret;
    if((ret = pcap_compile(handle,&filter,filter_ip.c_str(),1,0)) < 0)
    {
        fprintf(stderr,"compile error\n");
        return false;
    }

    if( ( ret = pcap_setfilter(handle,&filter)) <0 )
    {
        fprintf(stderr,"setfilter error\n");
        return false;
    }
    return true;
}

bool open_pcap_file(pcap_t** handle, const char* filename)
{
    char errBuff[PCAP_ERRBUF_SIZE];
    *handle = pcap_open_offline(filename, errBuff);
    if (NULL == *handle) 
	{
        fprintf(stderr, "Error: %s\n", errBuff);
        return (EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}

void readversion()
{
    //read the libpcap version
    static const char *version;
    version = pcap_lib_version();
    fprintf(stdout, "%s\n", version);
}

void readfile()
{
//    PCAP_PKTHEADER *pktHeader;
//    const u_char *pktData;
//    int status =  pcap_next_ex(handle, &pktHeader, &pktData);
//    int count = 0 ;

//    while(status == 1)
//    {
//        printPktHeader(pktHeader);
//        status = pcap_next_ex(handle,&pktHeader,&pktData);
//        printf("%d\n",++count);
//    }
}

namespace useless
{
    uint64_t current_pkt = 0;
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


}



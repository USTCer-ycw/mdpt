//
// Created by yaochuanwang on 10/9/20.
//

#include "src/Util/Pcapresolver.h"
#include <assert.h>
using namespace Mdpt;

PcapResolver::PcapResolver(pcap_t *handle) :
        header_(nullptr),
        handle_(handle),
        quit_(false)
{
    message_ = std::bind(&PcapResolver::defaultMessage, this, std::placeholders::_1);
}

PcapResolver::~PcapResolver()
{
    pcap_close(handle_);
    printf("close\n");
}

uint32_t PcapResolver::getSeqnum()
{
//    u_char *data = const_cast<u_char *>(data_);
    struct packet_ip* ip = static_cast<packet_ip*>(implicit_cast<void*>(data_ + SIZE_ETHERNET));
    u_char ipheaderlen = IP_HL(ip) << 2;
    struct packet_tcp* tcp = static_cast<packet_tcp*>(implicit_cast<void*>(data_ + SIZE_ETHERNET + ipheaderlen));
    return ntohl(tcp->th_seq);
}

string PcapResolver::getSrcIp()
{
//    u_char *data = const_cast<u_char *>(data_);
    struct packet_ip* ip = static_cast<packet_ip*>(implicit_cast<void*>(data_ + SIZE_ETHERNET));
    return inet_ntoa(ip->ip_src);
}

string PcapResolver::getDstIp()
{
    struct packet_ip* ip = static_cast<packet_ip*>(implicit_cast<void*>(data_ + SIZE_ETHERNET));
    return inet_ntoa(ip->ip_dst);
}

u_char * PcapResolver::getPayload()
{
    u_char *data = const_cast<u_char *>(data_);
    struct packet_ip* ip = static_cast<packet_ip*>(implicit_cast<void*>(data_ + SIZE_ETHERNET));
    u_char ipheaderlen = IP_HL(ip) << 2;
    struct packet_tcp* tcp = static_cast<packet_tcp*>(implicit_cast<void*>(data_ + SIZE_ETHERNET + ipheaderlen));
    u_char tcpheaderlen = TH_OFF(tcp) << 2;
    return data + SIZE_ETHERNET + ipheaderlen + tcpheaderlen;
}



void PcapResolver::defaultMessage(const PcapPtr &ptr)
{
    fprintf(stdout, "cap_time:%u, ", (unsigned int)header_->ts.tv_sec);
    fprintf(stdout, "pkt length:%u, ", header_->len);
    fprintf(stdout, "cap length:%u\n", header_->caplen);
}

void PcapResolver::poller()
{
    assert(handle_!=nullptr);
    int status = pcap_next_ex(handle_, const_cast<pcap_pkthdr **>(&header_), &data_);
    PcapPtr Ptr = shared_from_this();
    while (!quit_ && status == 1)
    {
        message_(Ptr);
        status = pcap_next_ex(handle_, const_cast<pcap_pkthdr **>(&header_), &data_);
    }
    if( status == 1)
    {
        message_(Ptr);
    }
}
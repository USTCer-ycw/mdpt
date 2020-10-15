//
// Created by yaochuanwang on 10/9/20.
//

#include "src/Util/Pcap.h"
#include "src/Util/Pcapresolver.h"
#include <assert.h>
using namespace Mdpt;

Pcap::Pcap() :
handle_(nullptr),
quit_(false)
{
//    message_ = std::bind(&Pcap::defaultCB, this, argument_, header_, data_);
}

Pcap::~Pcap()
{
//    pcap_close(handle_);
    printf("over\n");
}

void Pcap::setCallBack(const PcapMessageCB &cb)
{
    message_ = cb;
    pcapPtr_->setPcapMessage(std::move(message_));
}

void Pcap::defaultCB(u_char *argument, const struct pcap_pkthdr *header, const u_char *data)
{
    fprintf(stdout, "cap_time:%u, ", (unsigned int)header->ts.tv_sec);
    fprintf(stdout, "pkt length:%u, ", header->len);
    fprintf(stdout, "cap length:%u\n", header->caplen);
}

bool Pcap::open_pcap_file(const char *filename)
{
    char errBuff[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_offline(filename, errBuff);
    pcapPtr_ = std::make_shared<PcapResolver>(handle_);
    if (nullptr == handle_)
    {
        fprintf(stderr, "Error: %s\n", errBuff);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

bool Pcap::setsrcfilter(char *filterIP)
{
    assert(handle_ != nullptr);
    struct bpf_program filter;
    string src = "src";
    string filter_ip = src + filterIP;
    int ret;
    if ((ret = pcap_compile(handle_, &filter, filter_ip.c_str(), 1, 0)) < 0)
    {
        fprintf(stderr, "compile error\n");
        return false;
    }
    if ((ret = pcap_setfilter(handle_, &filter)) < 0)
    {
        fprintf(stderr, "setfilter error\n");
        return false;
    }
    return true;
}

void Pcap::loop()
{
    assert(handle_!=nullptr);
    assert(pcapPtr_.get() != nullptr);
    pcapPtr_->poller();
//    int status = pcap_next_ex(handle_, const_cast<pcap_pkthdr **>(&header_), &data_);
//    while (!quit_)
//    {
//        message_(argument_, header_, data_);
//        pcapPtr_->poller();
//        message_(pcapPtr_);
//        status = pcap_next_ex(handle_, const_cast<pcap_pkthdr **>(&header_), &data_);
//    }
//    if( status == 1)
//    {
//        message_(argument_, header_, data_);
//    }
}

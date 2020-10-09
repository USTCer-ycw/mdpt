//
// Created by yaochuanwang on 10/9/20.
//

#ifndef MDPT_PCAPRESOLVER_H
#define MDPT_PCAPRESOLVER_H
#include "src/Util/Pcap.h"
namespace Mdpt
{
    class PcapResolver : public std::enable_shared_from_this<PcapResolver>
    {
    public:
        using PcapPtr = std::shared_ptr<PcapResolver>;
        using PcapMessageCB = std::function<void(const PcapPtr&)>;
    public:
        explicit PcapResolver(pcap_t* handle);
        ~PcapResolver();
    public:
        void poller();
        void setPcapMessage(PcapMessageCB&& cb) { message_ = std::move(cb); }
        void defaultMessage(const PcapPtr& ptr);
        string getSrcIp();
        string getDstIp();
        uint32_t getSeqnum();
        u_char* getPayload();
        uint32_t getpacketlen() { return header_->len; }
        uint32_t getcaplen() { return header_->caplen; }
        struct timeval gettimeval() { return header_->ts; }
    private:
        u_char * argument_;
        pcap_t *handle_;
        struct pcap_pkthdr* header_;
        const u_char * data_;
        bool quit_;
        PcapMessageCB message_;
        PcapMessageCB defaultCB_;
    };
}

#endif //MDPT_PCAPRESOLVER_H

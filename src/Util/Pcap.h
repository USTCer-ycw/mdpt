//
// Created by yaochuanwang on 10/9/20.
//

#ifndef MDPT_PCAP_H
#define MDPT_PCAP_H
#include "src/Util/Util.h"
#include <functional>
#include <memory>
namespace Mdpt
{
    class PcapResolver;
    class Pcap
    {
    public:
//        using PcapMessageCB = std::function<void(u_char*, const struct pcap_pkthdr* , const u_char*)>;
        using PcapPtr = std::shared_ptr<PcapResolver>;
        using PcapMessageCB = std::function<void(const PcapPtr&)>;
    public:
        Pcap();
        ~Pcap();
    public:
        void setCallBack(const PcapMessageCB & cb);
        bool setsrcfilter(char* filterIP);
        bool open_pcap_file(const char* filename);
        void loop();
    private:
        void defaultCB(u_char*,const struct pcap_pkthdr*,const u_char*);
        PcapPtr pcapPtr_;
        pcap_t *handle_;
        PcapMessageCB message_;
        bool quit_;
    };


}

#endif //MDPT_PCAP_H

# mdpt

usage

define callback

void message(const Mdpt::PcapResolver::PcapPtr& Ptr)
{
    std::cout << Ptr->getSeqnum() << std:: endl;
    cout << Ptr->getSrcIp() << endl;
    cout << Ptr->getDstIp() << endl;
}

Mdpt::Pcap pcap;
pcap.open_pcap_file("haitong_sp.pcap");
pcap.setCallBack(std::bind(message, std::placeholders::_1));
pcap.loop();

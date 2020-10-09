
#include <time.h>
#include <iostream>
#include "src/Util/Pcapresolver.h"

using std::string;
using std::cout;
using std::endl;

void message(const Mdpt::PcapResolver::PcapPtr& Ptr)
{
    std::cout << Ptr->getSeqnum() << std:: endl;
    cout << Ptr->getSrcIp() << endl;
    cout << Ptr->getDstIp() << endl;
}

int main(int argc, char *argv[])
{
    fprintf(stdout, "beg time=%d\n", time(0));
    Mdpt::Pcap pcap;
    pcap.open_pcap_file("haitong_sp.pcap");
    pcap.setCallBack(std::bind(message, std::placeholders::_1));
    pcap.loop();
    fprintf(stdout, "end time=%d\n", time(0));
	return (EXIT_SUCCESS);
}


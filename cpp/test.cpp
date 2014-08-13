#include <tins/tins.h>
#include <map>
#include <iostream>
#include <functional>

using namespace Tins;

bool callback(const PDU &pkt) {
    const Dot11 &dot = pkt.rfind_pdu<Dot11>();
    std::cout << "Got a packet :P " << "\n" << dot.wep();
    return true;
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        std::cout << "Usage: " << *argv << " <interface>\n";
        return 1;
    }

    // Sniff on the provided interface in promiscuous mode
    Sniffer sniffer(argv[1], Sniffer::PROMISC);

    // Only capture arp packets
    //sniffer.set_filter("DOT11");

    sniffer.sniff_loop(callback);
}
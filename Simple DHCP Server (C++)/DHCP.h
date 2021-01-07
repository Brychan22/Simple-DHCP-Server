#pragma once
#include <vector>
#include <iostream>
#include "Net.h"
#include "Arduino.h"


class DHCP
{
public:
    
	static const unsigned char* MAGIC_COOKIE;
    unsigned int DHCPLeaseTime;

    std::vector<unsigned int> DNSServers;

    unsigned char maxLeases;

    unsigned char localAddress1;
    unsigned char localAddress2;
    unsigned char localAddress3;
    unsigned char deviceIP;

    unsigned char leaseStart;

    unsigned char localSubnet1;
    unsigned char localSubnet2;
    unsigned char localSubnet3;
    unsigned char localSubnet4;

    

    struct DHCPOption {
        unsigned char option = 0;
        std::vector<unsigned char> DHCPData;
        unsigned char dataLength = 0;
    };

    class DHCPEntry {
    public:
        Net::MACAddress MAC = Net::MACAddress::GetEmpty();
        unsigned int expiry = 0;
        std::vector<unsigned char> requestedItems;
    };
    DHCPEntry* DHCPEntries;

    //std::vector<DHCPEntry> DHCPEntries;

    unsigned char FindPosByMac(Net::MACAddress MAC, DHCPEntry* entries, unsigned char entries_size);

    std::vector<unsigned char> Generate_DHCP_Option(unsigned char option, unsigned char clientIP);

    std::vector<std::vector<unsigned char>> ProcessDHCP(unsigned char* rxBuffer, unsigned long bufferLength);

    DHCP(unsigned char* deviceAddress, unsigned char* subnetMask, unsigned char maxLeases, unsigned char leaseStart, unsigned int leaseTime, unsigned int* dnsServers, unsigned char dnsServerCount);
    ~DHCP();
};


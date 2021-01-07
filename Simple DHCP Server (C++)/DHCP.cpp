#include "DHCP.h"



static const unsigned char MAGIC_COOKIE_Data[] = { 0x63, 0x82, 0x53, 0x63 };
const unsigned char* DHCP::MAGIC_COOKIE = MAGIC_COOKIE_Data;

unsigned int DHCPLeaseTime = 900;

std::vector<unsigned int> DNSServers;

unsigned char maxLeases = 32;

unsigned char localAddress1 = 192;
unsigned char localAddress2 = 168;
unsigned char localAddress3 = 250;
unsigned char deviceIP = 1;

unsigned char leaseStart = 2;

unsigned char localSubnet1 = 255;
unsigned char localSubnet2 = 255;
unsigned char localSubnet3 = 255;
unsigned char localSubnet4 = 0;

DHCP::DHCPEntry* DHCPEntries;

//std::vector<DHCP::DHCPEntry> DHCPEntries(maxLeases);


std::vector<unsigned char> DHCP::Generate_DHCP_Option(unsigned char option, unsigned char clientIP) {
    std::vector<unsigned char> s;
    s.push_back(option);
    s.push_back(0);
    unsigned char length = 0;
    // Subnet
    if (option == 1) {
        s.push_back(localSubnet1);
        s.push_back(localSubnet2);
        s.push_back(localSubnet3);
        s.push_back(localSubnet4);
        length = 4;
    }
    else if (option == 3) {
        s.push_back(localAddress1);
        s.push_back(localAddress2);
        s.push_back(localAddress3);
        s.push_back(deviceIP);
        length = 4;
    }
    else if (option == 6) {
        if (DNSServers.size() > 0) {
            for (unsigned int i = 0; i < DNSServers.size(); i++)
            {
                if (DNSServers[i] != 0)
                {
                    s.push_back((unsigned char)(DNSServers[i] >> 24));
                    s.push_back((unsigned char)(DNSServers[i] >> 16));
                    s.push_back((unsigned char)(DNSServers[i] >> 8));
                    s.push_back((unsigned char)DNSServers[i]);
                    length += 4;
                }
            }
        }
        else return std::vector<unsigned char>(0);
    }
    else if (option == 51) {
        long time = 0;
        if (clientIP == 255) {
            time = DHCPLeaseTime;
        }
        else {
            time = DHCPEntries[clientIP - leaseStart].expiry - (Arduino::millis() / 1000);
        }
        s.push_back((unsigned char)(time >> 24));
        s.push_back((unsigned char)(time >> 16));
        s.push_back((unsigned char)(time >> 8));
        s.push_back((unsigned char)time);
        length = 4;
    }
    else if (option == 54) {
        s.push_back(localAddress1);
        s.push_back(localAddress2);
        s.push_back(localAddress3);
        s.push_back(deviceIP);
        length = 4;
    }
    else return std::vector<unsigned char>(0);
    s[1] = length;
    return s;
}

unsigned char DHCP::FindPosByMac(Net::MACAddress MAC, DHCP::DHCPEntry* entries, unsigned char entries_size) {
    for (unsigned char i = 0; i < entries_size; i++)
    {
        if (entries[i].MAC.equals(MAC)) {
            return i;
        }
    }
    return 255;
}



std::vector<std::vector<unsigned char>> DHCP::ProcessDHCP(unsigned char* rxBuffer, unsigned long bufferLength) {
    unsigned char txBuffer[Net::TYPICAL_MTU] = {}; // ensure we have base zeros
    u_long destAddress = 0xFFFFFFFF;
    if (rxBuffer[236] == DHCP::MAGIC_COOKIE[0] && rxBuffer[237] == DHCP::MAGIC_COOKIE[1] && rxBuffer[238] == DHCP::MAGIC_COOKIE[2] && rxBuffer[239] == DHCP::MAGIC_COOKIE[3]) {
        unsigned int position = 240;
        // Find all options
        std::vector<DHCP::DHCPOption> RXOptions;
        while (rxBuffer[position] != 0xFF && position < bufferLength) {
            unsigned char option = rxBuffer[position++];
            unsigned char dataLength = rxBuffer[position++];
            DHCP::DHCPOption newOption = DHCP::DHCPOption();
            newOption.option = option;
            newOption.dataLength = dataLength;

            while (dataLength > 0) {
                newOption.DHCPData.push_back(rxBuffer[position++]);
                dataLength--;
            }
            RXOptions.push_back(newOption);
        }
        // Check first option is DHCP
        if (RXOptions[0].option == 53) {
            Net::MACAddress clientMAC = Net::MACAddress((rxBuffer + 28));
            unsigned char leaseIndex = DHCP::FindPosByMac(clientMAC, DHCPEntries, maxLeases);
            unsigned char clientIP;
            if (leaseIndex == 255) {
                leaseIndex = FindPosByMac(Net::MACAddress::GetEmpty(), DHCPEntries, maxLeases);
                if (leaseIndex == 255) {
                    return std::vector<std::vector<unsigned char>>(0);
                }
            }
            clientIP = leaseIndex + leaseStart;
            txBuffer[0] = 2;
            for (unsigned char i = 1; i < 240; i++)
            {
                if (i == 12) {
                    i = 28;
                }
                else if (i == 44) {
                    i = 236;
                }
                txBuffer[i] = rxBuffer[i];
            }
            // Clear the rxBuffer, we have read all we need
            delete[] rxBuffer;

            txBuffer[16] = localAddress1;
            txBuffer[17] = localAddress2;
            txBuffer[18] = localAddress3;
            txBuffer[19] = clientIP;
            txBuffer[20] = localAddress1;
            txBuffer[21] = localAddress2;
            txBuffer[22] = localAddress3;
            txBuffer[23] = deviceIP;

            position = 240;
            // DHCP option
            if (RXOptions[0].DHCPData[0] == 1) {
                std::cout << "D";
                std::vector<unsigned char> prl;
                for (size_t i = 0; i < RXOptions.size(); i++)
                {
                    if (RXOptions[i].option == 50) {
                        unsigned char requestSuffix = RXOptions[i].DHCPData[RXOptions[i].dataLength - 1];
                        if (DHCPEntries[requestSuffix - leaseStart].MAC.equals(Net::MACAddress::GetEmpty())) {
                            clientIP = requestSuffix;
                            txBuffer[19] = clientIP;
                        }
                    }
                    else if (RXOptions[i].option == 55) {
                        prl.resize(RXOptions[i].dataLength);
                        for (size_t r = 0; r < RXOptions[i].dataLength; r++)
                        {
                            prl[r] = RXOptions[i].DHCPData[r];
                        }
                    }
                }
                DHCPEntries[clientIP - leaseStart].MAC = clientMAC;
                DHCPEntries[clientIP - leaseStart].requestedItems = prl;
                DHCPEntries[clientIP - leaseStart].expiry = (Arduino::millis() / 1000) + 30;

                txBuffer[position++] = 53;
                txBuffer[position++] = 1;
                txBuffer[position++] = 2;
                std::vector<unsigned char> r = Generate_DHCP_Option(54, clientIP);
                for (size_t i = 0; i < r.size(); i++)
                {
                    txBuffer[position++] = r[i];
                }
                r = Generate_DHCP_Option(51, clientIP);
                for (size_t i = 0; i < r.size(); i++)
                {
                    txBuffer[position++] = r[i];
                }
                for (size_t i = 0; i < prl.size(); i++)
                {
                    r = Generate_DHCP_Option(prl[i], clientIP);
                    if (r.size() > 0) {
                        for (size_t b = 0; b < r.size(); b++)
                        {
                            txBuffer[position++] = r[b];
                        }
                    }
                }
                std::cout << "O";
            }
            else if (RXOptions[0].DHCPData[0] == 3) {
                std::cout << "R";
                bool optionsMatch = true;
                for (size_t i = 0; i < RXOptions.size(); i++)
                {
                    if (RXOptions[i].option == 50) {
                        if (clientIP != RXOptions[i].DHCPData[RXOptions[i].dataLength - 1] && !DHCPEntries[clientIP - 2].MAC.equals(Net::MACAddress::GetEmpty())) {
                            optionsMatch = false;
                            break;
                        }
                    }
                    else if (RXOptions[i].option == 54) {
                        if (deviceIP != RXOptions[i].DHCPData[RXOptions[i].dataLength - 1]) {
                            optionsMatch = false;
                            break;
                        }
                    }
                    else if (RXOptions[i].option == 55) {
                        DHCPEntries[clientIP - leaseStart].requestedItems.clear();
                        DHCPEntries[clientIP - leaseStart].requestedItems.resize(RXOptions[i].dataLength);
                        for (size_t r = 0; r < RXOptions[i].dataLength; r++) {
                            DHCPEntries[clientIP - leaseStart].requestedItems[r] = RXOptions[i].DHCPData[r];
                        }

                    }
                }
                if (optionsMatch) {
                    // Ack
                    DHCPEntries[clientIP - leaseStart].expiry = (Arduino::millis() / 1000) + DHCPLeaseTime;

                    txBuffer[position++] = 53;
                    txBuffer[position++] = 1;
                    txBuffer[position++] = 5; // ACK
                    std::vector<unsigned char> r = Generate_DHCP_Option(54, clientIP);
                    for (size_t i = 0; i < r.size(); i++)
                    {
                        txBuffer[position++] = r[i];
                    }
                    r = Generate_DHCP_Option(51, clientIP);
                    for (size_t i = 0; i < r.size(); i++)
                    {
                        txBuffer[position++] = r[i];
                    }
                    for (size_t i = 0; i < DHCPEntries[clientIP - leaseStart].requestedItems.size(); i++)
                    {
                        r = Generate_DHCP_Option(DHCPEntries[clientIP - leaseStart].requestedItems[i], clientIP);
                        if (r.size() > 0) {
                            for (size_t b = 0; b < r.size(); b++)
                            {
                                txBuffer[position++] = r[b];
                            }
                        }
                    }
                    std::cout << "A\n";
                }
                else {
                    txBuffer[position++] = 53;
                    txBuffer[position++] = 1;
                    txBuffer[position++] = 5; // ACK
                    std::vector<unsigned char> r = Generate_DHCP_Option(54, clientIP);
                    for (size_t i = 0; i < r.size(); i++)
                    {
                        txBuffer[position++] = r[i];
                    }
                    r = Generate_DHCP_Option(51, clientIP);
                    for (size_t i = 0; i < r.size(); i++)
                    {
                        txBuffer[position++] = r[i];
                    }
                    for (size_t i = 0; i < DHCPEntries[clientIP - leaseStart].requestedItems.size(); i++)
                    {
                        r = Generate_DHCP_Option(DHCPEntries[clientIP - leaseStart].requestedItems[i], clientIP);
                        if (r.size() > 0) {
                            for (size_t b = 0; b < r.size(); b++)
                            {
                                txBuffer[position++] = r[b];
                            }
                        }
                    }
                    std::cout << "N\n";
                }
            }
            else {
                std::cout << " " << RXOptions[0].DHCPData[0] << "\n";
            }
        }
        txBuffer[position++] = 255;
        std::vector<unsigned char> returnBuffer(position);
        for (size_t i = 0; i < position; i++)
        {
            returnBuffer[i] = txBuffer[i];
        }
        
        return std::vector<std::vector<unsigned char>> {std::vector<unsigned char> {(unsigned char)(destAddress >> 24), (unsigned char)(destAddress >> 16), (unsigned char)(destAddress >> 8), (unsigned char)destAddress}, returnBuffer};
    }
    return std::vector<std::vector<unsigned char>>(0);
}
DHCP::DHCP(unsigned char* deviceAddress, unsigned char* subnetMask, unsigned char maxLeases, unsigned char leaseStart, unsigned int leaseTime, unsigned int* dnsServers, unsigned char dnsServerCount) {
    localAddress1 = deviceAddress[0];
    localAddress2 = deviceAddress[1];
    localAddress3 = deviceAddress[2];
    deviceIP = deviceAddress[3];

    localSubnet1 = subnetMask[0];
    localSubnet2 = subnetMask[1];
    localSubnet3 = subnetMask[2];
    localSubnet4 = subnetMask[3];

    this->maxLeases = maxLeases;
    this->leaseStart = leaseStart;
    DHCPLeaseTime = leaseTime;
    DHCPEntries = new DHCP::DHCPEntry[maxLeases];
    DNSServers.resize(dnsServerCount);
    for (size_t i = 0; i < dnsServerCount; i++)
    {
        DNSServers[i] = dnsServers[i];
    }
}

DHCP::~DHCP() {
    delete[] DHCPEntries;
}
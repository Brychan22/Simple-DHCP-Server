// Simple DHCP Server (C++).cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <vector>
#include <string>
#pragma comment(lib, "WS2_32.lib")

const unsigned char MAGIC_COOKIE[] = { 0x63, 0x82, 0x53, 0x63 };
const short STANDARD_MTU = 1480;

static unsigned int DHCPLeaseTime = 900;

static std::vector<unsigned int> DNSServers = {16843009};

static unsigned char maxLeases = 32;

static unsigned char localAddress1 = 192;
static unsigned char localAddress2 = 168;
static unsigned char localAddress3 = 250;
static unsigned char deviceIP = 1;

static unsigned char leaseStart = 2;

static unsigned char localSubnet1 = 255;
static unsigned char localSubnet2 = 255;
static unsigned char localSubnet3 = 255;
static unsigned char localSubnet4 = 0;

struct MACAddress {
private:
    char MACSize;
    std::vector<unsigned char> MACBytes;
public:
    MACAddress(unsigned char c1, unsigned char c2, unsigned char c3, unsigned char c4, unsigned char c5, unsigned char c6)
    {
        MACBytes = std::vector<unsigned char>{c1,c2,c3,c4,c5,c6};
        MACSize = 6;
    }
    MACAddress(unsigned char *byteArray, char length) {
        MACBytes = std::vector<unsigned char>(length);
        for (char i = 0; i < length; i++)
        {
            MACBytes[i] = *byteArray;
            byteArray++;
        }
        MACSize = length;
    }
    MACAddress(std::vector<unsigned char> bytes) {
        MACBytes = bytes;
        MACSize = bytes.size();
    }
    char getMACSize() {
        return MACSize;
    }
    std::vector<unsigned char> getMACBytes() {
        return MACBytes;
    }

    bool equals(MACAddress other) {
        if (MACSize != other.getMACSize()) {
            return false;
        }
        for (unsigned char i = 0; i < MACSize; i++)
        {
            if (MACBytes[i] != other.getMACBytes()[i]) {
                return false;
             }
        }
        return true;
    }
    static MACAddress GetEmpty() {
        return MACAddress(0, 0, 0, 0, 0, 0);
    }
};

struct DHCPOption {
    unsigned char option = 0;
    std::vector<unsigned char> DHCPData;
    unsigned char dataLength = 0;
};

class DHCPEntry {
public:
    MACAddress MAC = MACAddress::GetEmpty();
    unsigned int expiry = 0;
    std::vector<unsigned char> requestedItems;
};


static std::vector<DHCPEntry> DHCPEntries(maxLeases);

// Maintain a C#-esque network client for simple handling
// As per https://stackoverflow.com/questions/14665543/how-do-i-receive-udp-packets-with-winsock-in-c
// A handler class is helpful. This implementation is based on the implementation in .NET
struct IPAddress {
private:
    u_char address[4];
public:
    IPAddress() 
    {
        address[0] = 0;
        address[1] = 0;
        address[2] = 0;
        address[3] = 0;
    }
    IPAddress(u_char c1, u_char c2, u_char c3, u_char c4) {
        address[0] = c1;
        address[1] = c2;
        address[2] = c3;
        address[3] = c4;
    }

    IPAddress(u_char* IP) {
        address[0] = *IP;
        address[1] = *(IP+1);
        address[2] = *(IP+2);
        address[3] = *(IP+3);
    }

    static IPAddress Empty() {
        return IPAddress();
    }

    bool Equals(IPAddress other) {
        for (byte i = 0; i < 4; i++)
        {
            if (address[i] != other.address[i]) {
                return false;
            }
        }
        return true;
    }
};

struct IPEndPoint {
    struct sockaddr_in socks;
    IPAddress Address;

    IPEndPoint(u_char* IP, u_short Port) {
        Address = IPAddress(IP);
        //std::string strIP = std::to_string(IP[0]) + std::to_string('.') + std::to_string(IP[1]) + std::to_string('.') + std::to_string(IP[2]) + std::to_string('.') + std::to_string(IP[3]);
        socks.sin_family = AF_INET;
        u_char c1 = IP[0];
        u_char c2 = IP[1];
        u_char c3 = IP[2];
        u_char c4 = IP[3];
        u_long r = (c4 << 24) | (c3 << 16) | (c2 << 8) | c1; // Are these swapped?
        socks.sin_addr.S_un.S_addr = r;//  inet_pton(AF_INET, strIP, );//inet_addr(IP);
        socks.sin_port = htons(Port);
    }
};

class UdpClient {
    struct Socket {
        struct sockaddr_in socks;
        SOCKET sock;
        void Bind(IPEndPoint ep) {
            int r = bind(sock, (SOCKADDR*)&ep.socks, sizeof(ep.socks));
            int reslt = WSAGetLastError();
            if (r < 0) {
                
                throw std::system_error(reslt, std::system_category(), "Could not bind socket");
            }
            int broadcast = 1;
            setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof broadcast);
        }

        void Bind(u_char *IP, u_short Port) {
            IPEndPoint ep = IPEndPoint(IP, Port);
            Bind(ep);
        }
    };

public:
    Socket Client;
    UdpClient() {
        // We're a UDP Client; set socket mode to IPv4 UDP Datagrams
        this->Client.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }

    std::vector<u_char> Recieve(IPEndPoint* remote) {
        std::vector<u_char> recievedBytes;
        char buffer[1024];
        int remoteSize = sizeof(remote->socks);
        int r = recvfrom(Client.sock, buffer, 1024, 0, (SOCKADDR*)&remote->socks, &remoteSize);
        if (r > 0) {
            recievedBytes.resize(r);
            for (int i = 0; i < r; i++)
            {
                recievedBytes[i] = buffer[i];
            }
        }
        return recievedBytes;
    }
    void Send(std::vector<u_char> Datagram, int dGramSize, IPEndPoint ep) {
        char dgData[STANDARD_MTU];
        for (size_t i = 0; i < dGramSize; i++)
        {
            dgData[i] = Datagram[i];
        }
        int result = sendto(Client.sock, dgData, dGramSize, 0, (SOCKADDR*)&ep.socks, sizeof (ep.socks));
        int reslt = WSAGetLastError();
        int g = 200;
    }

    void Send(std::vector<u_char> Datagram, int dGramSize, std::vector<u_char> DestinationIP, int DestPort) {
        IPEndPoint ep = IPEndPoint(DestinationIP.data(), (u_short)DestPort);
        Send(Datagram, dGramSize, ep);
    }

    
};

static u_int millis() {
    return (u_int)(GetTickCount64() % UINT32_MAX);
}

static u_char FindPosByMac(MACAddress MAC, std::vector<DHCPEntry> entries, u_char entries_size) {
    for (size_t i = 0; i < entries_size; i++)
    {
        if (entries[i].MAC.equals(MAC)) {
            return i;
        }
    }
    return 255;
}

static std::vector<u_char> Generate_DHCP_Option(u_char option, u_char clientIP) {
    std::vector<u_char> s;
    s.push_back(option);
    s.push_back(0);
    u_char length = 0;
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
            for (size_t i = 0; i < DNSServers.size(); i++)
            {
                if (DNSServers[i] != 0)
                {
                    s.push_back((size_t)(DNSServers[i] >> 24));
                    s.push_back((size_t)(DNSServers[i] >> 16));
                    s.push_back((size_t)(DNSServers[i] >> 8));
                    s.push_back((size_t)DNSServers[i]);
                    length += 4;
                }
            }
        }
        else return std::vector<u_char>(0);
    }
    else if (option == 51) {
        long time = 0;
        if (clientIP == 255) {
            time = DHCPLeaseTime;
        }
        else {
            time = DHCPEntries[clientIP - leaseStart].expiry - (millis() / 1000);
        }
        s.push_back((u_char)(time >> 24));
        s.push_back((u_char)(time >> 16));
        s.push_back((u_char)(time >> 8));
        s.push_back((u_char)time);
        length = 4;
    }
    else if (option == 54) {
        s.push_back(localAddress1);
        s.push_back(localAddress2);
        s.push_back(localAddress3);
        s.push_back(deviceIP);
        length = 4;
    }
    else return std::vector<u_char>(0);
    s[1] = length;
    return s;
}

std::vector<std::vector<u_char>> ProcessDHCP(std::vector<u_char> rxBuffer) {
    u_char txBuffer[STANDARD_MTU] = {}; // ensure we have base zeros
    u_long destAddress = ULLONG_MAX;
    if (rxBuffer[236] == MAGIC_COOKIE[0] && rxBuffer[237] == MAGIC_COOKIE[1] && rxBuffer[238] == MAGIC_COOKIE[2] && rxBuffer[239] == MAGIC_COOKIE[3]) {
        u_int position = 240;
        // Find all options
        std::vector<DHCPOption> RXOptions;
        while (rxBuffer[position] != 0xFF && position < STANDARD_MTU) {
            u_char option = rxBuffer[position++];
            u_char dataLength = rxBuffer[position++];
            DHCPOption newOption = DHCPOption();
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
            MACAddress clientMAC = MACAddress((rxBuffer.data()+28), 6);
            u_char leaseIndex = FindPosByMac(clientMAC, DHCPEntries, maxLeases);
            u_char clientIP;
            if (leaseIndex == 255) {
                leaseIndex = FindPosByMac(MACAddress::GetEmpty(), DHCPEntries, maxLeases);
                if (leaseIndex == 255) {
                    return std::vector<std::vector<u_char>>(0);
                }
            }
            clientIP = leaseIndex + leaseStart;
            txBuffer[0] = 2;
            for (u_char i = 1; i < 240; i++)
            {
                if (i == 12) {
                    i = 28;
                }
                else if (i == 44) {
                    i = 236;
                }
                txBuffer[i] = rxBuffer[i];
            }
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
                std::vector<u_char> prl;
                for (size_t i = 0; i < RXOptions.size(); i++)
                {
                    if (RXOptions[i].option == 50) {
                        u_char requestSuffix = RXOptions[i].DHCPData[RXOptions[i].dataLength - 1];
                        if (DHCPEntries[requestSuffix - leaseStart].MAC.equals(MACAddress::GetEmpty())) {
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
                DHCPEntries[clientIP - leaseStart].expiry = (millis() / 1000) + 30;

                txBuffer[position++] = 53;
                txBuffer[position++] = 1;
                txBuffer[position++] = 2;
                std::vector<u_char> r = Generate_DHCP_Option(54, clientIP);
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
                        if (clientIP != RXOptions[i].DHCPData[RXOptions[i].dataLength - 1] && !DHCPEntries[clientIP - 2].MAC.equals(MACAddress::GetEmpty())) {
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
                    DHCPEntries[clientIP - leaseStart].expiry = (millis() / 1000) + DHCPLeaseTime;

                    txBuffer[position++] = 53;
                    txBuffer[position++] = 1;
                    txBuffer[position++] = 5; // ACK
                    std::vector<u_char> r = Generate_DHCP_Option(54, clientIP);
                    for (size_t i = 0; i < r.size(); i++)
                    {
                        txBuffer[position++] = r[i];
                    }
                    r = Generate_DHCP_Option(51, clientIP);
                    for (size_t i = 0; i < r.size(); i++)
                    {
                        txBuffer[position++] = r[i];
                    }
                    for (size_t i = 0; i < DHCPEntries[clientIP-leaseStart].requestedItems.size(); i++)
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
                    std::vector<u_char> r = Generate_DHCP_Option(54, clientIP);
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
        std::vector<u_char> returnBuffer(position);
        for (size_t i = 0; i < position; i++)
        {
            returnBuffer[i] = txBuffer[i];
        }
        return std::vector<std::vector<u_char>> {std::vector<u_char> {(u_char)(destAddress >> 24), (u_char)(destAddress >> 16), (u_char)(destAddress >> 8), (u_char)destAddress}, returnBuffer};
    }
}

int main()
{
    std::cout << "Creating DHCP Server...\n";
    WORD wVersionRequested;
    WSADATA wsaData;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    int err = WSAStartup(wVersionRequested, &wsaData);
    // Does a vector need the items to be instanced?
    /*for (unsigned char i = 0; i < maxLeases; i++)
    {
         DHCPEntries[i] = new
    } */
    // This is platform-dependant; it opens a UDP socket and sends the packet data through
    // Create an IPv4 UDP Datagram socket
    UdpClient udpClient = UdpClient();
    udpClient.Client.Bind(IPEndPoint(new u_char[] {localAddress1, localAddress2, localAddress3, deviceIP}, 67));
    IPEndPoint remote = IPEndPoint(new u_char[] {0, 0, 0, 0}, 0);
    while (true) {
        std::vector<u_char> buffer = udpClient.Recieve(&remote);
        std::vector<std::vector<u_char>> result = ProcessDHCP(buffer);
        if (result.size() == 2) {
            if (remote.Address.Equals(IPAddress::Empty())) {
                udpClient.Send(result[1], result[1].size(), result[0], 68);
            }
            else {
                udpClient.Send(result[1], result[1].size(), remote);
                // Reply via return address
            }
        }
        
    }
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

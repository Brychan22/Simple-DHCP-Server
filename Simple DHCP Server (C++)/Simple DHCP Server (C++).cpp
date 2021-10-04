// Simple DHCP Server (C++).cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include "Net.h"
#include "DHCP.h"

// Maintain a C#-esque network client for simple handling
// As per https://stackoverflow.com/questions/14665543/how-do-i-receive-udp-packets-with-winsock-in-c
// A handler class is helpful. This implementation is based on the implementation in .NET

int main()
{
    std::cout << "Creating DHCP Server...\n";
    std::vector<unsigned long> servers;
    servers.push_back(0x1010101);
    DHCP dhcp = DHCP((192 << 24 ) |  (168 << 16 ) | (250 << 8) | 1 , 0xFFFFFF00, 32, 2, 900, servers, 1); // 0xFFFFFF00 = 255.255.255.0; 0x1010101 = 1.1.1.1
    Net::UdpClient udpClient = Net::UdpClient();
    udpClient.Client.Bind(Net::IPEndPoint((dhcp.localAddress1 << 24) | (dhcp.localAddress2 << 16) | (dhcp.localAddress3 << 8) | dhcp.deviceIP, 67));
    
    Net::IPEndPoint remote = Net::IPEndPoint(0, 0);
    unsigned long waitingBytes = 0;
    while (true) {
        waitingBytes = udpClient.Available();
        if (waitingBytes > 240) { // DHCP requires *at least* 240 bytes, the packet is malformed or incorrect if it is less
            unsigned char* buffBytes = udpClient.Recieve(&remote, (unsigned short)waitingBytes);
            std::vector<std::vector<unsigned char>> result = dhcp.ProcessDHCP(buffBytes, waitingBytes);
            delete[] buffBytes; // Handle the assigned buffer array
            if (result.size() == 2) {
                if (remote.Address.Equals(Net::IPAddress::Empty())) {
                    udpClient.Send(result[1], result[0], 68);
                }
                else {
                    udpClient.Send(result[1], remote);
                }
            }
        }
        // Artificial delay, to prevent hyperactive looping
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

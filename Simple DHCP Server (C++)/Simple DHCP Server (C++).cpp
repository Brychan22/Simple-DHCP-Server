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
    DHCP dhcp = DHCP(new unsigned char[] {192, 168, 250, 1}, new unsigned char[] {255, 255, 255, 0}, 32, 2, 900, new unsigned int[] { 16843009 }, 1);
    Net::UdpClient udpClient = Net::UdpClient();
    udpClient.Client.Bind(Net::IPEndPoint(new unsigned char[] {dhcp.localAddress1, dhcp.localAddress2, dhcp.localAddress3, dhcp.deviceIP}, 67));
    Net::IPEndPoint remote = Net::IPEndPoint(new unsigned char[] {0, 0, 0, 0}, 0);
    unsigned long waitingBytes = 0;
    while (true) {
        waitingBytes = udpClient.Available();
        if (waitingBytes > 240) { // DHCP requires *at least* 240 bytes, the packet is malformed or incorrect if it is less
            std::vector<std::vector<unsigned char>> result = dhcp.ProcessDHCP(udpClient.Recieve(&remote, (unsigned short)waitingBytes), waitingBytes);
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

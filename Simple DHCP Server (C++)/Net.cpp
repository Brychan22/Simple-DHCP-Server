#include "Net.h"
Net::IPAddress::IPAddress()
{
	address[0] = 0;
	address[1] = 0;
	address[2] = 0;
	address[3] = 0;
}
Net::IPAddress::IPAddress(unsigned char c1, unsigned char c2, unsigned char c3, unsigned char c4) {
	address[0] = c1;
	address[1] = c2;
	address[2] = c3;
	address[3] = c4;
}

Net::IPAddress::IPAddress(unsigned char* IP) {
	address[0] = *IP;
	address[1] = *(IP + 1);
	address[2] = *(IP + 2);
	address[3] = *(IP + 3);
}

Net::IPAddress Net::IPAddress::Empty() {
	return IPAddress::IPAddress();
}

bool Net::IPAddress::Equals(IPAddress other) {
	for (unsigned char i = 0; i < 4; i++)
	{
		if (address[i] != other.address[i]) {
			return false;
		}
	}
	return true;
}

Net::IPEndPoint::IPEndPoint(unsigned char* IP, unsigned short Port) {
	Address = IPAddress(IP);
	socks.sin_family = AF_INET;
	socks.sin_addr.S_un.S_addr = (IP[3] << 24) | (IP[2] << 16) | (IP[1] << 8) | IP[0]; // Order of the IP bytes is swapped, so 192.168.1.32 would be 32.1.168.192
	socks.sin_port = htons(Port); // Likewise, the port is also byte-order reversed.
}

Net::UdpClient::UdpClient() {
	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD(2, 2);
	int err = WSAStartup(wVersionRequested, &wsaData);
	if (err < 0) {

	}
	// We're a UDP Client; set socket mode to IPv4 UDP Datagrams
	this->Client.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

void Net::UdpClient::Socket::Bind(IPEndPoint ep) {
	int r = bind(sock, (SOCKADDR*)&ep.socks, sizeof(ep.socks));
	int reslt = WSAGetLastError();
	if (r < 0) {

		throw std::system_error(reslt, std::system_category(), "Could not bind socket");
	}
	int broadcast = 1;
	setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof broadcast);
}

void Net::UdpClient::Socket::Bind(unsigned char* IP, unsigned short Port) {
	IPEndPoint ep = IPEndPoint(IP, Port);
	Bind(ep);
}

unsigned char* Net::UdpClient::Recieve(IPEndPoint* remote, unsigned short BufferSize) {
	char* buffer = new char[BufferSize];
	int remoteSize = sizeof(remote->socks);
	int r = recvfrom(Client.sock, buffer, BufferSize, 0, (SOCKADDR*)&remote->socks, &remoteSize);
	return reinterpret_cast<unsigned char*>(buffer);
}
int Net::UdpClient::Send(char* Datagram, short DatagramSize, IPEndPoint ep) {
	return sendto(Client.sock, Datagram, DatagramSize, 0, (SOCKADDR*)&ep.socks, sizeof(ep.socks));
}

int Net::UdpClient::Send(std::vector<unsigned char> Datagram, IPEndPoint ep) {
	return Send(reinterpret_cast<char*>(Datagram.data()), (short)Datagram.size(), ep);
}

int Net::UdpClient::Send(std::vector<unsigned char> Datagram, std::vector<unsigned char> DestinationIP, int DestPort) {
	IPEndPoint ep = IPEndPoint(DestinationIP.data(), (u_short)DestPort);
	return Send(Datagram, ep);
}

int Net::UdpClient::Available()
{
	unsigned long availableBytes = 0;
	int result = ioctlsocket(Client.sock, FIONREAD, &availableBytes);
	if (result != 0) {
		// Error occured
	}
	return availableBytes;
}

Net::MACAddress::MACAddress(unsigned char c1, unsigned char c2, unsigned char c3, unsigned char c4, unsigned char c5, unsigned char c6)
{
	macBytes[0] = c1;
	macBytes[1] = c2;
	macBytes[2] = c3;
	macBytes[3] = c4;
	macBytes[4] = c5;
	macBytes[5] = c6;
}
Net::MACAddress::MACAddress(unsigned char* byteArray) {
	for (size_t i = 0; i < MACSize; i++)
	{
		macBytes[i] = byteArray[i];
	}
}
Net::MACAddress::MACAddress(std::vector<unsigned char> bytes) {
	for (size_t i = 0; i < MACSize; i++)
	{
		macBytes[i] = bytes[i];
	}
}

bool Net::MACAddress::equals(MACAddress other) {
	for (unsigned char i = 0; i < MACSize; i++)
	{
		if (macBytes[i] != other.macBytes[i]) {
			return false;
		}
	}
	return true;
}


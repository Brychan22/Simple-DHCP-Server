#pragma once
#include <memory>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <system_error>
#include <vector>
#pragma comment(lib, "WS2_32.lib")
class Net {
public:
	static const unsigned short TYPICAL_MTU = 1480;
	static const unsigned char MACSize = 6;

	struct IPAddress {
	private:
		unsigned char address[4];
	public:
		IPAddress();
		IPAddress(unsigned char c1, unsigned char c2, unsigned char c3, unsigned char c4);

		IPAddress(unsigned long IP);

		static IPAddress Empty();

		bool Equals(IPAddress other);
	};

	struct IPEndPoint {
		struct sockaddr_in socks;
		IPAddress Address;

		IPEndPoint(unsigned long IP, unsigned short Port);
	};

	class UdpClient {
		struct Socket {
			struct sockaddr_in socks;
			SOCKET sock;
			void Bind(IPEndPoint ep);

			void Bind(unsigned long IP, unsigned short Port);
		};

	public:
		Socket Client;
		UdpClient();

		unsigned char* Recieve(IPEndPoint* remote, unsigned short BufferSize = 1480);
		int Send(char* Datagram, short DatagramSize, IPEndPoint ep);

		int Send(std::vector<unsigned char> Datagram, IPEndPoint ep);
		/// <summary>
		/// Sends the data in Datagram to the destination IP address &amp; port.
		/// </summary>
		/// <param name="Datagram">A std::vector&lt;u_char&gt; of the data to be sent</param>
		/// <param name="DestinationIP">The destination IP address (Little Endian)</param>
		/// <param name="DestPort">The destination port (Little Endian)</param>
		/// <returns>A value less than zero if an error occured</returns>
		int Send(std::vector<unsigned char> Datagram, std::vector<unsigned char> DestinationIP, int DestPort);
		/// <summary>
		/// Gets the amount of bytes available, or zero if no connection is yet available
		/// </summary>
		/// <returns></returns>
		int Available();
	};

	struct MACAddress {
		unsigned char macBytes[6];
		MACAddress(unsigned char c1, unsigned char c2, unsigned char c3, unsigned char c4, unsigned char c5, unsigned char c6);
		MACAddress(unsigned char* byteArray);
		MACAddress(std::vector<unsigned char> bytes);

		bool equals(MACAddress other);

		static MACAddress GetEmpty() {
			return MACAddress(0, 0, 0, 0, 0, 0);
		}
	};
};



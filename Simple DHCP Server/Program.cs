using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace Simple_DHCP_Server
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Creating DHCP Server...");
            DHCP dhcp = new DHCP(new byte[] {192,168,250,1 }, new byte[] {255,255,255,0 }, 32, 2, 900, new uint[] { 16_843_009, });
            UdpClient udpClient = new UdpClient();
            //udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 67));
            udpClient.Client.Bind(new IPEndPoint(IPAddress.Parse("192.168.250.1"), 67));
            // Keep track of the remote IP, if it exists
            IPEndPoint remote = new IPEndPoint(0, 0);
            while (true)
            {
                // Possibility to multithread this, though for the microprocessor, we will remain single threaded

                if (udpClient.Available > 0)
                {
                    byte[] buffer = udpClient.Receive(ref remote);
                    if (remote.Address.GetAddressBytes()[2] != 2)
                    {
                        try
                        {
                            Tuple<string, byte[]> result = dhcp.ProcessDHCP(buffer, udpClient);
                            // Return data to the remote endpoint, if it has a valid IP, else we just broadcast the packet
                            if (remote.Address.Equals(IPAddress.Parse("0.0.0.0")))
                            {
                                udpClient.Send(result.Item2, result.Item2.Length, result.Item1, 68);
                            }
                            else
                            {
                                udpClient.Send(result.Item2, result.Item2.Length, remote);
                            }

                        }
                        catch (NullReferenceException)
                        {
                            Console.WriteLine("Data invalid");
                        }
                    }
                }
                // Clean the DHCP table as necessary
                dhcp.ProcessDHCPTable();
                Thread.Sleep(1);
            }
        }        
    }

    class Arduino
    {
        /// <summary>
        /// returns a similar expected value as to millis() in Arduino (milliseconds since system start; rolls over)
        /// This in 
        /// </summary>
        /// <returns></returns>
        public static uint millis()
        {
            return (uint)(GetTickCount64() % uint.MaxValue);
        }

        [DllImport("kernel32")]
        extern static UInt64 GetTickCount64();
    }
}

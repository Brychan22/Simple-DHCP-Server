using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Simple_DHCP_Server
{
    class Program
    {
        static byte[] MAGIC_COOKIE = { 0x63, 0x82, 0x53, 0x63 };
        const short STANDARD_MTU = 1480;
        static uint DHCPLeaseTime = 900; // 15 minutes

        static uint[] DNSServers = new uint[] { 16_843_009, }; // 1.1.1.1

        // NEW
        // Local network IP address
        static byte localAddress1 = 192;
        static byte localAddress2 = 168;
        static byte localAddress3 = 250;
        static byte deviceIP = 1;

        static byte leaseStart = 2;

        // Local Subnet Address
        static byte localSubnet1 = 255;
        static byte localSubnet2 = 255;
        static byte localSubnet3 = 255;
        static byte localSubnet4 = 0;

        // This option is used on Init() to prereserve lease space (in RAM) for this many devices
        // Take note that each lease uses 25 bytes, minimum, so 128 leases = 3.2 kB RAM
        // As this server is intended to run only IPv4, we can crop the MAC address to 6 bytes + 10*zero,
        // giving 15/bytes entry (total of 1.92 kB initially)
        // Storing hashes of the MAC address should result in faster lookups, though at the cost of 2n space.
        // (so 1.92 kB is actually 2.176 kB)
        static byte maxLeases = 32;

        static DHCPEntry[] DHCPEntries = new DHCPEntry[maxLeases];
        static int[] DHCPHashes = new int[maxLeases];

        static void Main(string[] args)
        {
            Console.WriteLine("Creating DHCP Server...");
            for (int i = 0; i < maxLeases; i++)
            {
                DHCPEntries[i] = new DHCPEntry();
            }
            UdpClient udpClient = new UdpClient();
            //udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 67));
            udpClient.Client.Bind(new IPEndPoint(IPAddress.Parse("192.168.250.1"), 67));
            // Keep track of the remote IP, if it exists
            IPEndPoint remote = new IPEndPoint(0, 0);
            while (true)
            {
                // Possibility to multithread this, though for the microprocessor, we will remain single threaded
                byte[] buffer = udpClient.Receive(ref remote);
                if (remote.Address.GetAddressBytes()[2] != 2)
                {
                    try
                    {
                        Tuple<string, byte[]> result = ProcessDHCP(buffer, udpClient);
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
                // Clean the DHCP table as necessary
                ProcessDHCPTable();
            }
        }

        public static Tuple<string, byte[]> ProcessDHCP(byte[] rxBuffer, UdpClient client)
        {
            // Reserve the standard MTU as DHCP packets should not be broken - might get resized as options sizes are calculated
            byte[] txBuffer = new byte[STANDARD_MTU];
            string destAddress = "255.255.255.255"; // Broadcast
            if (rxBuffer[236] == MAGIC_COOKIE[0] && rxBuffer[237] == MAGIC_COOKIE[1] && rxBuffer[238] == MAGIC_COOKIE[2] && rxBuffer[239] == MAGIC_COOKIE[3])
            {
                // Jump to after the magic packet
                uint position = 240;
                // To avoid excessive memory usage (and as DHCP messages require >~700 bytes of data), we create the output
                // buffer and write directly to it as data is processed.
                // This helps keep memory free, and allows quicker processing of the data.
                // However, we must first identify the type of DHCP operation expected to be performed


                // Begin by identifying the options requested,
                // Assume DHCP Option (53) is the first element
                List<DHCPOption> RXOptions = new List<DHCPOption>();
                // Iterate through the remaining buffer while the current position is not too far & the value at this position is not 255
                while (rxBuffer[position] != 0xFF && position < STANDARD_MTU)
                {
                    byte option = rxBuffer[position++];
                    // Read the data length from the option
                    byte dataLength = rxBuffer[position++];
                    DHCPOption newOption = new DHCPOption()
                    {
                        option = option,
                        dataLength = dataLength
                    };
                    while (dataLength > 0)
                    {
                        newOption.DHCPData.Add(rxBuffer[position++]);
                        dataLength--;
                    }
                    RXOptions.Add(newOption);
                }

                // Next, check that we start with a DHCP option
                if (RXOptions[0].option == 53)
                {
                    // Grab the MAC address object, so we can compare with the existing items
                    MACAddress clientMAC = new MACAddress(rxBuffer[28..34]); // take the range of values from 28 (inclusive) to 34 (exclusive) i.e. 6 bytes of MAC address
                    // Find if the item already exists, and/or determine its IP now
                    byte leaseIndex = FindPosByMac(clientMAC, DHCPEntries, maxLeases);
                    byte clientIP = 0;
                    if (leaseIndex < 255)
                    {
                        // If found, use the client's assigned IP address
                        clientIP =(byte)(leaseIndex + leaseStart);
                    }
                    else
                    {
                        // Not found; search for the next empty MAC and assign 
                        leaseIndex = FindPosByMac(MACAddress.Empty, DHCPEntries, maxLeases);
                        if (leaseIndex == 255)
                        {
                            return null;
                        }
                        clientIP = (byte)(leaseIndex + leaseStart);
                    }
                    // The same basic packet structure occurs to all responses:
                    // In context, we're always responding
                    txBuffer[0] = 2;
                    // The following duplicates the HTYPE, LEN, HOPS, XID, SECS, FLAGS fields, as they are not expected to change
                    for (byte i = 1; i < 12; i++)
                    {
                        txBuffer[i] = rxBuffer[i];
                    }
                    // The mac address [28..34] is 16 bytes long, 6 bytes followed by 10 zeros
                    // We can just copy this from the client's message
                    for (byte i = 28; i < 44; i++)
                    {
                        txBuffer[i] = rxBuffer[i];
                    }
                    // Copy magic packet
                    for (int i = 236; i < 240; i++)
                    {
                        txBuffer[i] = rxBuffer[i];
                    }
                    // Now, all responses include our address (20-24) and your address (16-20)
                    txBuffer[16] = localAddress1;
                    txBuffer[17] = localAddress2;
                    txBuffer[18] = localAddress3;
                    txBuffer[19] = clientIP;
                    txBuffer[20] = localAddress1;
                    txBuffer[21] = localAddress2;
                    txBuffer[22] = localAddress3;
                    txBuffer[23] = deviceIP;


                    position = 240;
                    // Now, figure the DHCP option requested
                    if (RXOptions[0].DHCPData[0] == 1)
                    {
                        Console.Write("D");
                        byte[] prl = new byte[0];
                        // Sort through DHCP options
                        foreach (DHCPOption option in RXOptions)
                        {
                            // Ignore 53 as we've processed and its reply is done later
                            if (option.option == 50)
                            {
                                // Device has requested a specific IP; check if it is in use
                                byte requestSuffix = option.DHCPData[option.dataLength - 1];
                                if (DHCPEntries[requestSuffix-leaseStart].MAC.Equals(MACAddress.Empty))
                                {
                                    // No device under this lease; change our ip and assign this instead
                                    clientIP = requestSuffix;
                                    txBuffer[19] = clientIP;
                                }
                            }
                            else if(option.option == 55)
                            {
                                // Parameter request list
                                prl = new byte[option.dataLength];
                                for (int i = 0; i < option.dataLength; i++)
                                {
                                    prl[i] = option.DHCPData[i];
                                }
                            }
                        }
                        // We now have all the required data to formulate an Offer
                        // We make this offer for 30 seconds; if another Discover request is made, update the old time
                        // Begin by adding the Offer to the table
                        //DHCPEntries[clientIP - leaseStart].IpSuffix = clientIP;
                        DHCPEntries[clientIP - leaseStart].MAC = clientMAC;
                        DHCPEntries[clientIP - leaseStart].requestedItems = prl;
                        DHCPEntries[clientIP - leaseStart].expiry = (millis() / 1000) + 30; // Set the expiry 30 seconds from now
                        // Next formulate the options in the offer
                        // DHCP Option
                        txBuffer[position++] = 53;
                        txBuffer[position++] = 1;
                        txBuffer[position++] = 2;
                        // Must have lease time & DHCP Server
                        List<byte> r = Generate_DHCP_Option(54, clientIP);
                        foreach (byte b in r)
                        {
                            txBuffer[position++] = b;
                        }
                        r = Generate_DHCP_Option(51, clientIP);
                        foreach (byte b in r)
                        {
                            txBuffer[position++] = b;
                        }
                        // Requested Options
                        foreach (byte item in prl)
                        {
                            r = Generate_DHCP_Option(item, clientIP);
                            if (r != null)
                            {
                                for (int i = 0; i < r.Count; i++)
                                {
                                    txBuffer[position++] = r[i];
                                }
                            }
                            // We don't know how to handle this option, so ignore it
                        }
                        // Log our offer
                        Console.Write("O");
                    }
                    else if (RXOptions[0].DHCPData[0] == 3)
                    {
                        Console.Write("R");
                        bool optionsMatch = true;
                        foreach (DHCPOption option in RXOptions)
                        {
                            // Ignore 53 as we've processed and its reply is done later
                            // If 50 does not match our provided IP, reject the request (NACK)
                            if (option.option == 50)
                            {
                                // Should the entry not be initialised, just accept the client, despite the incorrect joining (maybe the server lost power?)
                                if (clientIP != option.DHCPData[option.dataLength - 1] && !DHCPEntries[clientIP-2].MAC.Equals(MACAddress.Empty))
                                {
                                    optionsMatch = false;
                                    break;
                                }
                            }
                            else if (option.option == 54)
                            {
                                // DHCP Server. Check that this matches our IP
                                if (deviceIP != option.DHCPData[option.dataLength - 1])
                                {
                                    optionsMatch = false;
                                    break;
                                }
                            }
                            else if (option.option == 55)
                            {
                                // Parameter request list
                                DHCPEntries[clientIP-2].requestedItems = new byte[option.dataLength];
                                for (int i = 0; i < option.dataLength; i++)
                                {
                                    DHCPEntries[clientIP - 2].requestedItems[i] = option.DHCPData[i];
                                }
                            }
                        }
                        if (optionsMatch)
                        {
                            // ACK
                            // Expiry is our current system time in seconds, (millis / 1000) + the lease time
                            DHCPEntries[clientIP - leaseStart].expiry = (millis() / 1000) + DHCPLeaseTime;
                            // Next formulate the options in the offer
                            // DHCP Option
                            txBuffer[position++] = 53;
                            txBuffer[position++] = 1;
                            txBuffer[position++] = 5; // Acknowledge
                            // Must have lease time & DHCP Server
                            List<byte> r = Generate_DHCP_Option(54, clientIP);
                            foreach (byte b in r)
                            {
                                txBuffer[position++] = b;
                            }
                            // Time must use the default value here; 255 isn't a valid client and the option generator uses 
                            r = Generate_DHCP_Option(51, clientIP);
                            foreach (byte b in r)
                            {
                                txBuffer[position++] = b;
                            }
                            // Requested Options
                            foreach (byte item in DHCPEntries[clientIP - leaseStart].requestedItems)
                            {
                                r = Generate_DHCP_Option(item, clientIP);
                                if (r != null)
                                {
                                    for (int i = 0; i < r.Count; i++)
                                    {
                                        txBuffer[position++] = r[i];
                                    }
                                }
                            }
                            // Log our offer
                            Console.WriteLine("A");
                        }
                        else
                        {
                            // NACK
                            txBuffer[position++] = 53;
                            txBuffer[position++] = 1;
                            txBuffer[position++] = 6; // Negative Acknowledge
                            // Must have lease time & DHCP Server
                            List<byte> r = Generate_DHCP_Option(54, clientIP);
                            foreach (byte b in r)
                            {
                                txBuffer[position++] = b;
                            }
                            // Time must use the default value here; 255 isn't a valid client and the option generator uses 
                            r = Generate_DHCP_Option(51, clientIP);
                            foreach (byte b in r)
                            {
                                txBuffer[position++] = b;
                            }
                            // Requested Options
                            foreach (byte item in DHCPEntries[clientIP - leaseStart].requestedItems)
                            {
                                r = Generate_DHCP_Option(item, clientIP);
                                if (r != null)
                                {
                                    for (int i = 0; i < r.Count; i++)
                                    {
                                        txBuffer[position++] = r[i];
                                    }
                                }
                            }
                            // Log our offer
                            Console.WriteLine("N");
                        }
                    }
                    else
                    {
                        Console.WriteLine(" " + RXOptions[0].DHCPData[0] + " ");
                    }
                }
                // Set the final byte high
                txBuffer[position++] = 255;
                byte[] returnBuffer = new byte[position];
                Array.Copy(txBuffer, returnBuffer, position);
                return new Tuple<string, byte[]>(destAddress, returnBuffer);
            }
            else
            {
                Console.WriteLine("Magic Cookie not found");
                return null;
            }
        }
        /// <summary>
        /// returns a similar expected value as to millis() in Arduino (milliseconds since system start; rolls over)
        /// This in 
        /// </summary>
        /// <returns></returns>
        public static uint millis()
        {
            TimeSpan elapsed = DateTime.Now.Subtract(Process.GetCurrentProcess().StartTime);
            return (uint)(GetTickCount64() % uint.MaxValue);
        }

        [DllImport("kernel32")]
        extern static UInt64 GetTickCount64();

        static uint GetIP(byte IpSuffix)
        {
            return (uint)((localAddress1 << 24) | (localAddress2 << 16) | (localAddress3 << 8) | IpSuffix);
        }

        static uint GetIP()
        {
            return GetIP(deviceIP);
        }
        /// <summary>
        /// returns 255 if not found.
        /// </summary>
        /// <param name="mac"></param>
        /// <param name="array"></param>
        /// <param name="arrayLimit"></param>
        /// <returns></returns>
        static byte FindPosByMac(MACAddress MAC, DHCPEntry[] array, byte arrayLimit)
        {
            for (byte i = 0; i < arrayLimit; i++)
            {
                if (array[i].MAC.Bytes == null) return 255;
                if (array[i].MAC.Equals(MAC))
                {
                    return i;
                }
            }
            return 255;
        }

        /// <summary>
        /// Searches the DHCP table for expired entries and removes them as appropriate
        /// (Also restructures the table)
        /// </summary>
        static void ProcessDHCPTable()
        {
            uint currentTime = millis() / 1000;
            for (int i = 0; i < maxLeases; i++)
            {
                if (DHCPEntries[i].expiry <= currentTime && !DHCPEntries[i].MAC.Equals(MACAddress.Empty))
                {
                    DHCPEntries[i].MAC = MACAddress.Empty;
                    // clear requested items
                    DHCPEntries[i].requestedItems = new byte[5];
                }
            }
        }

        /// <summary>
        /// Generates a DHCP option, by the provided code
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        static List<byte> Generate_DHCP_Option(byte option, byte clientIP)
        {
            List<byte> s = new List<byte>();
            s.Add(option);
            s.Add(0);
            byte length = 0;
            // Subnet code
            if (option == 1)
            {
                s.Add(localSubnet1);
                s.Add(localSubnet2);
                s.Add(localSubnet3);
                s.Add(localSubnet4);
                length = 4;
            }
            // Router
            else if (option == 3)
            {
                s.Add(localAddress1);
                s.Add(localAddress2);
                s.Add(localAddress3);
                s.Add(deviceIP);
                length = 4;
            }
            // DNS Servers
            else if (option == 6)
            {
                if (DNSServers.Length > 0)
                {
                    for (int i = 0; i < DNSServers.Length; i++)
                    {
                        if (DNSServers[i] != 0)
                        {
                            s.Add((byte)(DNSServers[i] >> 24));
                            s.Add((byte)(DNSServers[i] >> 16));
                            s.Add((byte)(DNSServers[i] >> 8));
                            s.Add((byte)DNSServers[i]);
                            length += 4;

                        }
                    }
                }
                else return null;
            }
            // Lease Time
            else if (option == 51)
            {
                long time = 0;
                if (clientIP == 255)
                {
                    time = DHCPLeaseTime;
                }
                else
                {
                    // As the time stored in DHCPEntries is in seconds, subtracting the current millis() in seconds
                    time = DHCPEntries[clientIP - 2].expiry - (millis()/1000);
                }
                s.Add((byte)(time >> 24));
                s.Add((byte)(time >> 16));
                s.Add((byte)(time >> 8));
                s.Add((byte)time);
                length = 4;
            }
            else if (option == 54)
            {
                s.Add(localAddress1);
                s.Add(localAddress2);
                s.Add(localAddress3);
                s.Add(deviceIP);
                length = 4;
            }
            else return null;

            s[1] = length;
            return s;
        }
    }
    class DHCPOption
    {
        public byte option=0;
        public List<byte> DHCPData = new List<byte>();
        public byte dataLength=0;
    }
    /// <summary>
    /// Initial size is 111 bytes / entry (theoretically)
    /// Can grow as necessary
    /// </summary>
    class DHCPEntry
    {
        //public byte IpSuffix = 0; // implied by position
        // Don't init the MAC, that must be done once the table is ready
        public MACAddress MAC = MACAddress.Empty;
        public uint expiry = 0; // 4
        public byte[] requestedItems = new byte[0];
    }

    /// <summary>
    /// NAT table entries keep track of the client endpoint for maintaining consistent communication via one gateway.
    /// (6 bytes/entry)
    /// </summary>
    class NATEntry
    {
        public byte sourceDevice = 0; // The device sends data through the socket <ip>:<port>
        public ushort sourcePort = 0;
        // This device rewrites the source port with a new one (below), and replaces the ip.
        public ushort destPort = 0;
        // Keep track of the connection state, setting this to closed if necessary
        public bool closed = false;
    }

    /// <summary>
    /// Represents a MAC address as a single object
    /// This should be approximately ported to c++, including the Equals() method,
    /// so that easy comparison of the MAC addresses can be performed
    /// </summary>
    struct MACAddress
    {
        byte _MACSize;
        byte[] MACbytes;
        public readonly static MACAddress Empty = new MACAddress(0, 0, 0, 0, 0, 0);
        
        public MACAddress(byte b1, byte b2, byte b3, byte b4, byte b5, byte b6)
        {
            MACbytes = new byte[] { b1, b2, b3, b4, b5, b6 };
            _MACSize = 6;
        }

        public MACAddress(byte[] bytes)
        {
            if (bytes.Length > byte.MaxValue) throw new IndexOutOfRangeException("Size of source byte array cannot exceed byte.MaxValue");
            MACbytes = new byte[bytes.Length];
            for (int i = 0; i < bytes.Length; i++)
            {
                MACbytes[i] = bytes[i];
            }
            _MACSize = (byte)bytes.Length;
        }

        public byte[] Bytes => MACbytes;
        public byte MACSize { get { return _MACSize; } }

        public override bool Equals(object obj)
        {
            try
            {
                if (MACSize != ((MACAddress)obj).MACSize)
                {
                    return false;
                }
                for (int i = 0; i < MACSize; i++)
                {
                    if (MACbytes[i] != ((MACAddress)obj).MACbytes[i])
                    {
                        return false;
                    }
                }
            }
            catch (InvalidCastException)
            {
                return false;
            }
            return true;
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
}

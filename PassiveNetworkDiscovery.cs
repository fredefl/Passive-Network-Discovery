using System;
using System.Collections.Generic;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;
using SharpPcap.WinPcap;
using PacketDotNet;
using System.Text;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Timers;
using MySql;
using MySql.Data.MySqlClient;

namespace PassiveNetworkDiscovery
{
    /// <summary>
    /// Basic capture example
    /// </summary>
    public class BasicCap
    {
        private static Dictionary<string,string> IpList = new Dictionary<string,string>();
        private static string FileName = DateTime.Now.ToString("dd MM yyyy HH mm ss") + ".txt";
        private static ICaptureDevice Device;
        private static int StatisticsInterval = 1000 * 10;

        private static MySqlConnection DatabaseConnection;
        private static string DatabaseHost = "127.0.0.1";
        private static string DatabasePort = "3306";
        private static string DatabaseUsername = "root";
        private static string DatabasePassword = "";
        private static string DatabaseSchema = "";
        private static string DatabaseTable = "";

        public static void Main(string[] Args)
        {
            int SpecifiedDevice = 0;
            try
            {
                foreach (string Argument in Args)
                {
                    if (Argument.StartsWith("d"))
                    {
                        SpecifiedDevice = Int32.Parse(Argument.Substring(2));
                    }
                    if (Argument.StartsWith("s"))
                    {
                        StatisticsInterval = Int32.Parse(Argument.Substring(2));
                    }
                    if (Argument.StartsWith("o"))
                    {
                        FileName = Argument.Substring(2);
                    }
                }
            }
            catch (Exception)
            {

            }
            
            // Print a welcome message
            Console.WriteLine("Welcome to Passive Network Discovery");

            LogFilePrompt:
            Console.WriteLine();
            Console.Write("Do you want use MySQL? [Y/n] ");
            ConsoleKeyInfo LogFileKey = Console.ReadKey();
            Console.WriteLine();
            Console.WriteLine();

            if (LogFileKey.KeyChar == 'n' || LogFileKey.KeyChar == 'N') {
                // Use files
                // Print log filename note
                Console.WriteLine();
                Console.WriteLine("NOTE: This program will log to {0}", FileName);
                
            }
            else if (LogFileKey.KeyChar == 'y' || LogFileKey.KeyChar == 'Y' || LogFileKey.Key == ConsoleKey.Enter)
            {
                // Use database
                Console.WriteLine("-- Connecting to MySQL server...");
                string DatabaseConnectionString = String.Format("server={0};port={1};user={2};password={3};database={4};", 
                    DatabaseHost, DatabasePort, DatabaseUsername, DatabasePassword, DatabaseSchema);

                DatabaseConnection = new MySqlConnection(DatabaseConnectionString);
                try
                {
                    DatabaseConnection.Open();
                    Console.WriteLine("-- Connected to MySQL server successfully!");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("-- Error while connecting to MySQL server!");
                    Console.WriteLine(ex.ToString());
                    Console.Read();
                    return;
                }


            }
            else
            {
                // Please try again
                Console.WriteLine();
                Console.WriteLine("Did not understand that, please try again!");
                goto LogFilePrompt;
            }

            // Retrieve the device list
            var Devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if (Devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            if (SpecifiedDevice == 0)
            {
                Console.WriteLine();
                Console.WriteLine("The following devices are available on this machine:");
                Console.WriteLine("----------------------------------------------------");
                Console.WriteLine();

                int i = 1;


                // Print out the devices
                foreach (var TempDevice in Devices)
                {
                    // Description
                    Console.WriteLine("{0}) {1} {2}", i, TempDevice.Name, TempDevice.Description);
                    i++;
                }

                Console.WriteLine();
                Console.Write("-- Please choose a device to capture: ");
                SpecifiedDevice = int.Parse(Console.ReadLine());
            }

            try
            {
                Device = Devices[SpecifiedDevice - 1];
            }
            catch (Exception)
            {
                Console.WriteLine("This device doesn't exist");
                return;
            }

            // Register our handler function to the 'packet arrival' event
            Device.OnPacketArrival += 
                new PacketArrivalEventHandler(OnPacketArrival);

            // Open the device for capturing
            int ReadTimeoutMilliseconds = 1000;
            if (Device is AirPcapDevice)
            {
                // NOTE: AirPcap devices cannot disable local capture
                var AirPcap = Device as AirPcapDevice;
                AirPcap.Open(SharpPcap.WinPcap.OpenFlags.DataTransferUdp, ReadTimeoutMilliseconds);
            }
            else if (Device is WinPcapDevice)
            {
                var WinPcap = Device as WinPcapDevice;
                WinPcap.Open(SharpPcap.WinPcap.OpenFlags.DataTransferUdp | SharpPcap.WinPcap.OpenFlags.NoCaptureLocal, ReadTimeoutMilliseconds);
            }
            else if (Device is LibPcapLiveDevice)
            {
                var LivePcapDevice = Device as LibPcapLiveDevice;
                LivePcapDevice.Open(DeviceMode.Promiscuous, ReadTimeoutMilliseconds);
            }
            else
            {
                throw new System.InvalidOperationException("unknown device type of " + Device.GetType().ToString());
            }

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, hit 'Ctrl + C' to stop...",
                Device.Name, Device.Description);

            Console.CancelKeyPress += delegate
            {
                // Stop the capturing process
                Device.StopCapture();

                Console.WriteLine();
                Console.WriteLine("-- Capture stopped.");

                // Close the pcap device
                Device.Close();
            };

            // Start the capturing process
            Device.StartCapture();

            Timer StatisticsTimer = new Timer();
            StatisticsTimer.Elapsed += new ElapsedEventHandler(DisplayStatisticsEvent);
            StatisticsTimer.Interval = StatisticsInterval;
            StatisticsTimer.Start();

            while (true) { Console.Read(); }
        }

        /// <summary>
        /// Displacs the statistics regularly
        /// </summary>
        /// <param name="source"></param>
        /// <param name="e"></param>
        private static void DisplayStatisticsEvent(object source, ElapsedEventArgs e)
        {
            Console.WriteLine("Received packets: {0}, Hosts: {1}", Device.Statistics.ReceivedPackets, IpList.Keys.Count);
        }

        /// <summary>
        /// Checks if the IP address is on one of the private subnets
        /// </summary>
        /// <param name="IpAddress"></param>
        /// <returns></returns>
        private static bool IsOnPrivateSubnet (string IpAddress)
        {
            return Regex.IsMatch(IpAddress, @"(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)");
        }

        /// <summary>
        /// Saves the log to file
        /// </summary>
        private static void SaveLog()
        {
            File.WriteAllLines(FileName,
                IpList.Select(x => x.Key + ";" + x.Value).ToArray());
        }

        /// <summary>
        /// Receives all packets and processes them
        /// </summary>
        private static void OnPacketArrival (object sender, CaptureEventArgs e)
        {
            try
            {
                // Parse the packet
                var raw_ip = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ip = IpPacket.GetEncapsulated(raw_ip);
                string IpAddress = ip.SourceAddress.ToString();

                // If source device isn't on one of the private subnets, ignore the packet
                if (!IsOnPrivateSubnet(IpAddress)) 
                    return;

                if (!IpList.ContainsKey(IpAddress))
                {
                    Console.WriteLine("Discovered new host: {0}", IpAddress);
                    IpList[IpAddress] = "";
                }
            }
            catch (Exception)
            {
                // If the packet isn't an IP packet, move on
            }
            try
            {
                // Parse the packet
                var RawArpPacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ArpPacket = ARPPacket.GetEncapsulated(RawArpPacket);

                // Source information
                string SourceIpAddress = ArpPacket.SenderProtocolAddress.ToString();
                string SourceMacAddress = BitConverter.ToString(ArpPacket.SenderHardwareAddress.GetAddressBytes()).ToLower().Replace("-", ":");
                
                // If source device isn't on one of the private subnets, ignore the packet
                if (!IsOnPrivateSubnet(SourceIpAddress))
                    return;

                // Target information
                string TargetIpAddress = ArpPacket.TargetProtocolAddress.ToString();
                string TargetMacAddress = BitConverter.ToString(ArpPacket.TargetHardwareAddress.GetAddressBytes()).ToLower().Replace("-", ":");

                // If target device isn't on one of the private subnets, ignore the packet
                if (!IsOnPrivateSubnet(TargetIpAddress))
                    return;

                // If source device isn't on one of the private subnets, ignore the packet
                if (!IsOnPrivateSubnet(TargetIpAddress))
                    return;

                if (SourceMacAddress != "ff:ff:ff:ff:ff:ff" && SourceMacAddress != "00:00:00:00:00:00")
                {
                    if (!IpList.ContainsKey(SourceIpAddress))
                    {
                        Console.WriteLine("Discovered new host: {0}", SourceIpAddress);
                    }
                    IpList[SourceIpAddress] = SourceMacAddress;
                }
                if (TargetMacAddress != "ff:ff:ff:ff:ff:ff" && TargetMacAddress != "00:00:00:00:00:00")
                {
                    if (!IpList.ContainsKey(TargetIpAddress))
                    {
                        Console.WriteLine("Discovered new host: {0}", TargetIpAddress);
                    }
                    IpList[TargetIpAddress] = TargetMacAddress;
                }
            }
            catch (Exception)
            {
                // If the packet isn't an ARP packet, move on
            }

            // Save the log file
            SaveLog();
        }
    }
}

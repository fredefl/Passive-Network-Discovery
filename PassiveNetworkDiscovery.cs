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
using System.Diagnostics;

namespace PassiveNetworkDiscovery
{
    public class Discovery
    {
        private static Dictionary<string,string> IpList = new Dictionary<string,string>();
        private static string FileName = DateTime.Now.ToString("dd MM yyyy HH mm ss") + ".txt";
        private static ICaptureDevice Device;
        private static int StatisticsInterval = 1000 * 10;
        private static long LastPacketCount = 0;

        private static MySqlConnection DatabaseConnection;
        private static MySqlConnection SecondDatabaseConnection;
        private static string DatabaseHost = "127.0.0.1";
        private static string DatabasePort = "3306";
        private static string DatabaseUsername = "root";
        private static string DatabasePassword = "";
        private static string DatabaseSchema = "passive_network_discovery";
        private static string DatabaseTable = "hosts";

        private const int DATABASE = 0;
        private const int FILE = 1;
        private static int LogType;

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
            ConsoleKeyInfo LogTypeKey = Console.ReadKey();
            Console.WriteLine();
            Console.WriteLine();

            if (LogTypeKey.KeyChar == 'n' || LogTypeKey.KeyChar == 'N')
            {
                // Use files
                LogType = FILE;
                // Print log filename note
                Console.WriteLine();
                Console.WriteLine("NOTE: This program will log to {0}", FileName);
                
            }
            else if (LogTypeKey.KeyChar == 'y' || LogTypeKey.KeyChar == 'Y' || LogTypeKey.Key == ConsoleKey.Enter)
            {
                // Use database
                LogType = DATABASE;
                Console.WriteLine("-- Connecting to MySQL server...");
                string DatabaseConnectionString = String.Format("server={0};port={1};user={2};password={3};database={4};", 
                    DatabaseHost, DatabasePort, DatabaseUsername, DatabasePassword, DatabaseSchema);

                DatabaseConnection = new MySqlConnection(DatabaseConnectionString);
                SecondDatabaseConnection = new MySqlConnection(DatabaseConnectionString);
                try
                {
                    DatabaseConnection.Open();
                    SecondDatabaseConnection.Open();
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
                try
                {
                    // Stop the capturing process
                    Device.StopCapture();

                    Console.WriteLine();
                    Console.WriteLine("-- Capture stopped.");

                    // Close the pcap device
                    Device.Close();
                    DatabaseConnection.Close();
                }
                catch (Exception ex)
                {
                    // We do not care - at all!
                }
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
            int HostCount = -1;
            long PacketCount = Device.Statistics.ReceivedPackets;
            long PacketsPerSecond = (PacketCount - LastPacketCount) / (StatisticsInterval / 1000);

            if (LogType == FILE)
            {
                HostCount = IpList.Keys.Count;
            }
            else if (LogType == DATABASE)
            {
                try
                {
                    // Create the query string
                    string QueryString = String.Format("SELECT count(*) FROM {0}", DatabaseTable);

                    // Create the command
                    MySqlCommand Command = new MySqlCommand(QueryString, SecondDatabaseConnection);

                    // Get the number of hosts
                    HostCount = int.Parse(Command.ExecuteScalar() + "");
                }
                catch (MySqlException ex)
                {

                }
            }
            
            Console.WriteLine("Received packets: {0}, Packets/second: {1}, Hosts: {2}", PacketCount, PacketsPerSecond, HostCount);

            LastPacketCount = PacketCount;
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

        private static void WriteDiscoveredMessage(string MacAddress, string IpAddress, string Method)
        {
            Console.WriteLine("Discovered new host {0}: {1}\t{2}", Method, IpAddress, MacAddress);
        }

        private static void CheckMacAndIp (string MacAddress, string IpAddress, string Method) {
            if (MacAddress != "ff:ff:ff:ff:ff:ff" && MacAddress != "00:00:00:00:00:00" && IsOnPrivateSubnet(IpAddress))
            {
                // If the logging type is file
                if (LogType == FILE) {
                    // Check if the IP address is not already in the list
                    if (!IpList.ContainsKey(IpAddress))
                    {
                        // Write it to the console if a new host has been discovered
                        WriteDiscoveredMessage(MacAddress, IpAddress, Method);
                    }
                    // Add or update it to the list
                    IpList[IpAddress] = MacAddress;
                }
                else if (LogType == DATABASE)
                {
                    // Create a query string that determines the number of hosts with that specific mac address
                    string QueryString = String.Format("SELECT count(*) FROM {0} WHERE ip='{1}'", DatabaseTable, IpAddress);

                    // Create the command
                    MySqlCommand Command = new MySqlCommand(QueryString, SecondDatabaseConnection);

                    // If there is no such mac address in the table
                    if (int.Parse(Command.ExecuteScalar() + "") == 0)
                    {
                        // Brag about the new host discovery!
                        WriteDiscoveredMessage(MacAddress, IpAddress, Method);
                    }

                    // Remove the host from the table
                    QueryString = String.Format("DELETE FROM {0} WHERE ip='{1}' OR mac='{2}'", DatabaseTable, IpAddress, MacAddress);
                    Command = new MySqlCommand(QueryString, DatabaseConnection);
                    Command.ExecuteNonQuery();

                    // Insert the host to the table
                    QueryString = String.Format("INSERT INTO {0} (ip, mac) VALUES('{1}','{2}')", DatabaseTable, IpAddress, MacAddress);
                    Command = new MySqlCommand(QueryString, DatabaseConnection);
                    Command.ExecuteNonQuery();
                }            
             }
        }

        /// <summary>
        /// Receives all packets and processes them
        /// </summary>
        private static void OnPacketArrival (object sender, CaptureEventArgs e)
        {
            try
            {
                // Parse the packet
                var RawIp = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var Ip = IpPacket.GetEncapsulated(RawIp);

                var RawEthernet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var Ethernet = EthernetPacket.GetEncapsulated(RawEthernet);
                string SourceIpAddress = Ip.SourceAddress.ToString();
                string SourceMacAddress = BitConverter.ToString(Ethernet.SourceHwAddress.GetAddressBytes()).ToLower().Replace("-", ":");
                string TargetMacAddress = BitConverter.ToString(Ethernet.DestinationHwAddress.GetAddressBytes()).ToLower().Replace("-", ":");
                string TargetIpAddress = Ip.DestinationAddress.ToString();

                try
                {
                    CheckMacAndIp(SourceMacAddress, SourceIpAddress, "Eth");
                    CheckMacAndIp(TargetMacAddress, TargetIpAddress, "Eth");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
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

                // Target information
                string TargetIpAddress = ArpPacket.TargetProtocolAddress.ToString();
                string TargetMacAddress = BitConverter.ToString(ArpPacket.TargetHardwareAddress.GetAddressBytes()).ToLower().Replace("-", ":");

                try
                {
                    CheckMacAndIp(SourceMacAddress, SourceIpAddress, "ARP");
                    CheckMacAndIp(TargetMacAddress, TargetIpAddress, "ARP");
                } catch (Exception ex) {
                    Console.WriteLine(ex.ToString());
                }
            }
            catch (Exception)
            {
                // If the packet isn't an ARP packet, move on
            }

            // Save the log file
            if (LogType == FILE) 
                SaveLog();
        }
    }
}

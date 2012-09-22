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

namespace PassiveNetworkDiscovery
{
    /// <summary>
    /// Basic capture example
    /// </summary>
    public class BasicCap
    {
        public static Dictionary<string,string> IpList = new Dictionary<string,string>();
        public static string FileName;

        public static void Main(string[] args)
        {
            FileName = DateTime.Now.ToString("dd MM yyyy HH mm ss") + ".txt";

            // Print SharpPcap version
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap {0}, Example3.BasicCap.cs", ver);

            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if(devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the devices
            foreach(var dev in devices)
            {
                /* Description */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse( Console.ReadLine() );

            var device = devices[i];

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += 
                new PacketArrivalEventHandler( device_OnPacketArrival );

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            if (device is AirPcapDevice)
            {
                // NOTE: AirPcap devices cannot disable local capture
                var airPcap = device as AirPcapDevice;
                airPcap.Open(SharpPcap.WinPcap.OpenFlags.DataTransferUdp, readTimeoutMilliseconds);
            }
            else if(device is WinPcapDevice)
            {
                var winPcap = device as WinPcapDevice;
                winPcap.Open(SharpPcap.WinPcap.OpenFlags.DataTransferUdp | SharpPcap.WinPcap.OpenFlags.NoCaptureLocal, readTimeoutMilliseconds);
            }
            else if (device is LibPcapLiveDevice)
            {
                var livePcapDevice = device as LibPcapLiveDevice;
                livePcapDevice.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            }
            else
            {
                throw new System.InvalidOperationException("unknown device type of " + device.GetType().ToString());
            }

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, hit 'Enter' to stop...",
                device.Name, device.Description);

            // Start the capturing process
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();

            Console.WriteLine("-- Capture stopped.");

            // Print out the device statistics
            Console.WriteLine(device.Statistics.ToString());

            // Close the pcap device
            device.Close();
        }

        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            try
            {
                var raw_ip = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ip = IpPacket.GetEncapsulated(raw_ip);
                string IpAddress = ip.SourceAddress.ToString();
                if (!IpList.ContainsKey(IpAddress))
                {
                    Console.WriteLine(IpAddress);
                    IpList.Add(IpAddress,"");
                }
            }
            catch (Exception ex)
            {

            }
            try
            {
                var raw_arp = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var arp = ARPPacket.GetEncapsulated(raw_arp);
                string SenderIpAddress = arp.SenderProtocolAddress.ToString();
                string SenderMacAddress = BitConverter.ToString(arp.SenderHardwareAddress.GetAddressBytes()).ToLower().Replace("-", ":");
                string TargetIpAddress = arp.TargetProtocolAddress.ToString();
                string TargetMacAddress = BitConverter.ToString(arp.TargetHardwareAddress.GetAddressBytes()).ToLower().Replace("-",":");

                if (TargetMacAddress != "ff:ff:ff:ff:ff:ff")
                {
                    IpList[SenderIpAddress] = SenderMacAddress;
                    IpList[TargetIpAddress] = TargetMacAddress;
                    Console.WriteLine("New ARP discovery");
                }
            }
            catch (Exception ex2)
            {
                //Console.WriteLine(ex2.Message);
            }
            File.WriteAllLines(FileName,
                IpList.Select(x => x.Key + ";" + x.Value).ToArray()); 
        }
    }
}

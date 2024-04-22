// Michal Balogh, xbalog06
// FIT VUT
// 2024

using PacketDotNet;
using NetworkSniffer.Enums;
using SharpPcap;

namespace NetworkSniffer;

// Class for parsing incoming packets
public static class PacketParser
{
    public static PacketData? Parse(RawCapture rawCapture, Options options)
    {
        try
        {
            Packet packet = Packet.ParsePacket(LinkLayers.Ethernet, rawCapture.Data);
            
            var ethernetPacket = packet.Extract<EthernetPacket>();
            if (ethernetPacket == null)
            {
                return null;
            }

            var ipPacket = packet.Extract<IPPacket>();

            if (TryParseArpPacket(packet, ethernetPacket, out var arpPacketData, rawCapture))
            {
                return arpPacketData;
            }

            if (TryParseIPPacket(options, ipPacket, ethernetPacket, rawCapture, out var ipPacketData))
            {
                return ipPacketData;
            }

            return null;
        }
        catch (Exception ex)
        {
            ExitHandler.ExitFailure($"Error parsing packet {ex.Message}", ExitCode.PacketParseError);
        }

        throw new InvalidOperationException();
    }

    private static bool TryParseIPPacket(Options options, IPPacket? ipPacket, EthernetPacket ethernetPacket,
        RawCapture rawCapture,
        out PacketData? packetData)
    {
        if (ipPacket != null)
        {
            string? protocolType = null;
            // Try to cast packet to ipv6 packet and then get the specific type 
            if (ipPacket is IPv6Packet { PayloadPacket: IcmpV6Packet icmpV6Packet })
            {
                switch (icmpV6Packet.Type)
                {
                    // ICMP6
                    case IcmpV6Type.EchoReply:
                        protocolType = "ICMPv6 echo response";
                        break;
                    case IcmpV6Type.EchoRequest:
                        protocolType = "ICMPv6 echo request";
                        break;
                    // NDP
                    case IcmpV6Type.RouterSolicitation:
                    case IcmpV6Type.RouterAdvertisement:
                    case IcmpV6Type.NeighborSolicitation:
                    case IcmpV6Type.NeighborAdvertisement:
                        if (!options.Ndp && (options.Mld || options.Icmp6))
                        {
                            packetData = null;
                            return true;
                        }

                        protocolType = "Ndp";
                        break;
                    // MLD
                    case IcmpV6Type.MulticastListenerDone:
                    case IcmpV6Type.MulticastListenerQuery:
                    case IcmpV6Type.MulticastListenerReport:
                    case IcmpV6Type.Version2MulticastListenerReport:
                        if (!options.Mld && (options.Ndp || options.Icmp6))
                        {
                            packetData = null;
                            return true;
                        }

                        protocolType = "Mld";
                        break;
                    default:
                        packetData = null;
                        return true;
                }
            }

            var packetToReturn = new PacketData(
                ethernetPacket.SourceHardwareAddress?.ToString(),
                ethernetPacket.DestinationHardwareAddress?.ToString(),
                protocolType ?? ipPacket.Protocol.ToString(),
                rawCapture.PacketLength.ToString(),
                rawCapture.Data,
                ipPacket.SourceAddress,
                ipPacket.DestinationAddress
            );
            AddPortIfUdpOrTcp(ipPacket, packetToReturn);

            packetData = packetToReturn;
            return true;
        }
        
        packetData = null;
        return false;
    }

    // TCP and UDP packets have also port numbers, add them
    private static void AddPortIfUdpOrTcp(IPPacket ipPacket, PacketData packetToReturn)
    {
        if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
        {
            packetToReturn.DstPort = tcpPacket.DestinationPort;
            packetToReturn.SrcPort = tcpPacket.SourcePort;
        }
        else if (ipPacket.PayloadPacket is UdpPacket udpPacket)
        {
            packetToReturn.DstPort = udpPacket.DestinationPort;
            packetToReturn.SrcPort = udpPacket.SourcePort;
        }
    }

    private static bool TryParseArpPacket(Packet packet, EthernetPacket ethernetPacket,
        out PacketData? packetToReturn, RawCapture rawCapture)
    {
        // Try cast the packet to arp packet, and then extract its data
        if (packet.PayloadPacket is ArpPacket arpPacket)
        {
            packetToReturn = new PacketData(
                ethernetPacket.SourceHardwareAddress.ToString(),
                ethernetPacket.DestinationHardwareAddress.ToString(),
                "Arp",
                rawCapture.PacketLength.ToString(),
                rawCapture.Data,
                arpPacket.SenderProtocolAddress,
                arpPacket.TargetProtocolAddress
            );
            return true;
        }

        packetToReturn = null;
        return false;
    }
}
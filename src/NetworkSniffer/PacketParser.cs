using PacketDotNet;
using NetworkSniffer.Enums;
using SharpPcap;

namespace NetworkSniffer
{
    public static class PacketParser
    {
        public static PacketData? Parse(RawCapture rawCapture, Options options)
        {
            try
            {
                Packet packet = Packet.ParsePacket(LinkLayers.Ethernet, rawCapture.Data);

                var ethernetPacket = packet.Extract<EthernetPacket>();
                
                var ipPacket = packet.Extract<IPPacket>();
                
                if (packet.PayloadPacket is ArpPacket arpPacket)
                {
                    return new PacketData(
                        ethernetPacket?.SourceHardwareAddress?.ToString(), 
                        ethernetPacket?.DestinationHardwareAddress?.ToString(), 
                        "Arp",
                        rawCapture.Data.Length.ToString(),
                        packet.Bytes,
                        arpPacket.SenderProtocolAddress,
                        arpPacket.TargetProtocolAddress
                    );
                }
                else if (ipPacket != null)
                {
                    if (ipPacket is IPv6Packet { PayloadPacket: IcmpV6Packet icmpV6Packet } ipv6Packet)
                    {
                        Console.WriteLine(icmpV6Packet.Type);
                        string protocolType;
                        switch (icmpV6Packet.Type)
                        {
                            case IcmpV6Type.EchoReply:
                                protocolType = "ICMPv6 echo response";
                                break;
                            case IcmpV6Type.EchoRequest:
                                protocolType = "ICMPv6 echo request";
                                break;
                            case IcmpV6Type.RouterSolicitation:
                            case IcmpV6Type.RouterAdvertisement:
                            case IcmpV6Type.NeighborSolicitation:
                            case IcmpV6Type.NeighborAdvertisement:
                                if (!options.Ndp && (options.Mld || options.Icmp6))
                                {
                                    return null;
                                }
                                protocolType = "Ndp";
                                break;
                            case IcmpV6Type.MulticastListenerDone:
                            case IcmpV6Type.MulticastListenerQuery:
                            case IcmpV6Type.MulticastListenerReport:
                            case IcmpV6Type.Version2MulticastListenerReport:
                                if (!options.Mld && (options.Ndp || options.Icmp6))
                                {
                                    return null;
                                }
                                protocolType = "Mld";
                                break;
                            default:
                                return null;
                        }
                        return new PacketData(
                            ethernetPacket?.SourceHardwareAddress?.ToString(),
                            ethernetPacket?.DestinationHardwareAddress?.ToString(),
                            protocolType,
                            rawCapture.Data.Length.ToString(),
                            packet.Bytes,
                            ipv6Packet.SourceAddress,
                            ipv6Packet.DestinationAddress
                        );
                    }
                    var packetToReturn = new PacketData(
                        ethernetPacket?.SourceHardwareAddress?.ToString(), 
                        ethernetPacket?.DestinationHardwareAddress?.ToString(), 
                        ipPacket.Protocol.ToString(),
                        rawCapture.Data.Length.ToString(),
                        packet.Bytes,
                        ipPacket.SourceAddress,
                        ipPacket.DestinationAddress
                    );
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

                    return packetToReturn;
                }
                
                return null;
            }
            catch (Exception ex)
            {
                ExitHandler.ExitFailure($"Error parsing packet {ex.Message}", ExitCode.PacketParseError);
            }
            throw new InvalidOperationException();
        }
    }
}

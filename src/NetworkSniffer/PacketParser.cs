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
                if (ethernetPacket == null)
                {
                    return null;
                }
                
                var ipPacket = packet.Extract<IPPacket>();
                
                if (packet.PayloadPacket is ArpPacket arpPacket)
                {
                    return new PacketData(
                        ethernetPacket.SourceHardwareAddress.ToString(),
                        ethernetPacket.DestinationHardwareAddress.ToString(),
                        "Arp",
                        ethernetPacket.TotalPacketLength.ToString(),
                        packet.Bytes,
                        arpPacket.SenderProtocolAddress,
                        arpPacket.TargetProtocolAddress
                    );
                }
                else if (ipPacket != null)
                {
                    string? protocolType = null;
                    if (ipPacket is IPv6Packet { PayloadPacket: IcmpV6Packet icmpV6Packet })
                    {
                        switch (icmpV6Packet.Type)
                        {
                            case IcmpV6Type.EchoReply:
                                if (options.Icmp6 == false)
                                {
                                    return null;
                                }
                                protocolType = "ICMPv6 echo response";
                                break;
                            case IcmpV6Type.EchoRequest:
                                protocolType = "ICMPv6 echo request";
                                if (options.Icmp6 == false)
                                {
                                    return null;
                                }
                                break;
                            case IcmpV6Type.RouterSolicitation:
                            case IcmpV6Type.RouterAdvertisement:
                            case IcmpV6Type.NeighborSolicitation:
                            case IcmpV6Type.NeighborAdvertisement:
                                if (options is { Mld: true, Ndp: false, Icmp6: false })
                                {
                                    return null;
                                }
                                protocolType = "Ndp";
                                break;
                            case IcmpV6Type.MulticastListenerDone:
                            case IcmpV6Type.MulticastListenerQuery:
                            case IcmpV6Type.MulticastListenerReport:
                            case IcmpV6Type.Version2MulticastListenerReport:
                                if (options is { Mld: false, Ndp: true, Icmp6: false})
                                {
                                    return null;
                                }
                                protocolType = "Mld";
                                break;
                            default:
                                return null;
                        }
                        
                    }
                    var packetToReturn = new PacketData(
                        ethernetPacket.SourceHardwareAddress?.ToString(), 
                        ethernetPacket.DestinationHardwareAddress?.ToString(), 
                        protocolType ?? ipPacket.Protocol.ToString(),
                        ethernetPacket.TotalPacketLength.ToString(),
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

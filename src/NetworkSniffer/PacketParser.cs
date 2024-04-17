using PacketDotNet;
using NetworkSniffer.Enums;
using SharpPcap;

namespace NetworkSniffer
{
    public static class PacketParser
    {
        public static PacketData? Parse(RawCapture rawCapture)
        {
            try
            {
                Packet packet = Packet.ParsePacket(LinkLayers.Ethernet, rawCapture.Data);

                var ethernetPacket = packet.Extract<EthernetPacket>();
                
                var ipPacket = packet.Extract<IPPacket>();
                
                if (packet.PayloadPacket is ArpPacket arpPacket)
                {
                    return new PacketData(
                        ethernetPacket?.DestinationHardwareAddress?.ToString(), 
                        ethernetPacket?.SourceHardwareAddress?.ToString(), 
                        "Arp",
                        rawCapture.Data.Length.ToString(),
                        packet.Bytes,
                        arpPacket.SenderProtocolAddress,
                        arpPacket.TargetProtocolAddress
                    );
                }
                else if (ipPacket != null)
                {
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

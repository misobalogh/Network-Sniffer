using PacketDotNet;
using NetworkSniffer.Enums;
using SharpPcap;

namespace NetworkSniffer;

public static class PacketParser
{
    public static PacketData Parse(RawCapture rawCapture)
    {
        try
        {
            Packet packet = Packet.ParsePacket(LinkLayers.Ethernet, rawCapture.Data);
            
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket != null)
            {
                return new PacketData(
                    ipPacket.DestinationAddress.ToString(),
                    ipPacket.SourceAddress.ToString(),
                    ipPacket.Protocol.ToString(),
                    rawCapture.Data.Length.ToString(),
                    ipPacket.SourceAddress.ToString(),
                    ipPacket.DestinationAddress.ToString(),
                    "N/A",
                    "N/A",
                    packet.Bytes
                );
            }
            else
            {
                return new PacketData("Unknown", "Unknown", "Unknown", packet.Bytes.Length.ToString(), "Unknown", "Unknown", "N/A", "N/A", packet.Bytes);
            }
        }
        catch (Exception ex)
        {
            ExitHandler.ExitFailure($"Error parsing packet {ex.Message}", ExitCode.PacketParseError);
        }
        throw new InvalidOperationException();
    }
}


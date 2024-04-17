using System.Net;

namespace NetworkSniffer;

public class PacketData
{
    public PacketData(string? dstMac, string? srcMac, string protocol, string frameLength,  byte[] byteOffset, IPAddress? srcIp = null, IPAddress? dstIp = null, ushort? srcPort = null, ushort? dstPort = null)
    {
        SrcMac = ParseMac(srcMac);
        DstMac = ParseMac(dstMac);
        Protocol = protocol;
        FrameLength = frameLength;
        SrcIP = srcIp?.ToString();
        DstIP = dstIp?.ToString();
        SrcPort = srcPort;
        DstPort = dstPort;
        ByteOffset = byteOffset;
    }

    private string? ParseMac(string? macAddress)
    {
        if (string.IsNullOrEmpty(macAddress))
        {
            return null;
        }
        if (macAddress.Length != 12)
        {
            throw new ArgumentException("Invalid MAC address format", nameof(macAddress));
        }

        var formattedMac = string.Join(":", Enumerable.Range(0, 6)
            .Select(i => macAddress.Substring(i * 2, 2)));

        return formattedMac;
    }


    public string? SrcMac { get; set; }
    public string? DstMac { get; set; }
    public string Protocol { get; set; }
    public string FrameLength { get; set; }
    public string? Timestamp { get; set; }
    public string? SrcIP { get; set; }
    public string? DstIP { get; set; }
    public ushort? SrcPort { get; set; }
    public ushort? DstPort { get; set; }
    public byte[] ByteOffset { get; set; }
}
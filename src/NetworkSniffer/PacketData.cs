using System.Net;
using System.Text;

namespace NetworkSniffer;

public class PacketData
{
    public PacketData(string? srcMac, string? dstMac, string protocol, string frameLength,  byte[] byteOffset, IPAddress? srcIp = null, IPAddress? dstIp = null, ushort? srcPort = null, ushort? dstPort = null)
    {
        SrcMac = FormatMac(srcMac);
        DstMac = FormatMac(dstMac);
        Protocol = protocol;
        FrameLength = frameLength;
        SrcIP = srcIp?.ToString();
        DstIP = dstIp?.ToString();
        SrcPort = srcPort;
        DstPort = dstPort;
        ByteOffset = byteOffset;
    }

    private string? FormatMac(string? macAddress)
    {
        if (string.IsNullOrEmpty(macAddress))
        {
            return null;
        }
        
        if (macAddress.Length != 12)
        {
            throw new ArgumentException("Invalid MAC address format", macAddress);
        }

        var formattedMac = new StringBuilder();
        for (int i = 0; i < macAddress.Length; i += 2)
        {
            formattedMac.Append(macAddress.Substring(i, 2));
            formattedMac.Append(":");
        }

        formattedMac.Remove(formattedMac.Length - 1, 1);
        return formattedMac.ToString();
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
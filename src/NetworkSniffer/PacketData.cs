// Michal Balogh, xbalog06
// FIT VUT
// 2024

using System.Net;
using System.Text;

namespace NetworkSniffer;

// Class for storing data from packets
public class PacketData(
    string? srcMac,
    string? dstMac,
    string protocol,
    string frameLength,
    byte[] byteOffset,
    IPAddress? srcIp = null,
    IPAddress? dstIp = null,
    ushort? srcPort = null,
    ushort? dstPort = null)
{
    // Method for formatting MAC address in following format:
    //  00:00:00:00:00:00
    private static string? FormatMac(string? macAddress)
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
        // Iterate trough the mac address and append colon after each pair
        for (var i = 0; i < macAddress.Length; i += 2)
        {
            formattedMac.Append(macAddress.AsSpan(i, 2));
            formattedMac.Append(':');
        }
        
        // remove trailing colon
        formattedMac.Remove(formattedMac.Length - 1, 1);
        
        return formattedMac.ToString().ToLower();
    }

    public string? SrcMac { get; } = FormatMac(srcMac);
    public string? DstMac { get; } = FormatMac(dstMac);
    public string Protocol { get; } = protocol;
    public string FrameLength { get; } = frameLength;
    public string? Timestamp { get; set; }
    public string? SrcIP { get; } = srcIp?.ToString();
    public string? DstIP { get; } = dstIp?.ToString();
    public ushort? SrcPort { get; set; } = srcPort;
    public ushort? DstPort { get; set; } = dstPort;
    public byte[] ByteOffset { get; } = byteOffset;
}
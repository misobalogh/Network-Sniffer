namespace NetworkSniffer;

public class PacketData(string dstMac, string srcMac, string protocol, string frameLength, string srcIp, string dstIp, string srcPort, string dstPort, byte[] byteOffset)
{
    public string SrcMac { get; set; } = srcMac;
    public string DstMac { get; set; } = dstMac;
    public string Protocol { get; set; } = protocol;
    public string FrameLength { get; set; } = frameLength;
    public string? Timestamp { get; set; }
    public string SrcIP { get; set; } = srcIp;
    public string DstIP { get; set; } = dstIp;
    public string SrcPort { get; set; } = srcPort;
    public string DstPort { get; set; } = dstPort;
    public byte[] ByteOffset { get; set; } = byteOffset;
}
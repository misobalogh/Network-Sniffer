using System.Text;

namespace NetworkSniffer;

public static class OutputFormater
{
    public static void Output(PacketData packetData)
    {
        Console.WriteLine($"{packetData.Protocol}");
        Console.WriteLine("--------------------------------------------");
        Console.WriteLine($"timestamp: {packetData.Timestamp}");
        Console.WriteLine($"src MAC: {packetData.SrcMac}");
        Console.WriteLine($"dst MAC: {packetData.DstMac}");
        Console.WriteLine($"frame length: {packetData.FrameLength} bytes");
        Console.WriteLine($"src IP: {packetData.SrcIP}");
        Console.WriteLine($"dst IP: {packetData.DstIP}");
        if (packetData.SrcPort != null)
        {
            Console.WriteLine($"src port: {packetData.SrcPort}");
        }
        if (packetData.DstPort != null)
        {
            Console.WriteLine($"dst port: {packetData.DstPort}");
        }
        Console.WriteLine();
        
        for (var i = 0; i < packetData.ByteOffset.Length; i += 16)
        {
            // length of current line - either 16 or remaining bytes for last line
            int lengthCurrentLine = Math.Min(16, packetData.ByteOffset.Length - i);
            
            // beginning of the line
            string byteOffset = $"0x{i:X4}: ";
            
            string byteOffsetHexa = BitConverter.ToString(packetData.ByteOffset, i, lengthCurrentLine).Replace('-', ' ').ToLower();

            string byteOffsetASCII = Encoding.ASCII.GetString(packetData.ByteOffset, i, lengthCurrentLine);
            for (int j = 0; j < byteOffsetASCII.Length; j++)
            {
                if (byteOffsetASCII[j] < 32 || byteOffsetASCII[j] > 126)
                {
                    byteOffsetASCII = byteOffsetASCII.Remove(j, 1).Insert(j, ".");
                }
            }

            Console.WriteLine($"{byteOffset,-8}{byteOffsetHexa,-48}{byteOffsetASCII}");
        }
        
        Console.WriteLine("--------------------------------------------");
        Console.WriteLine();
    }
}
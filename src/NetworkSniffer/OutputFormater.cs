using System.Text;

namespace NetworkSniffer;

public static class OutputFomater
{
    public static void Output(PacketData packetData)
    {
        Console.WriteLine("--------------------------------------------");
        Console.WriteLine($"timestamp: {packetData.Timestamp}");
        Console.WriteLine($"src MAC: {packetData.SrcMac}");
        Console.WriteLine($"dst MAC: {packetData.DstMac}");
        Console.WriteLine($"frame length: {packetData.FrameLength}");
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
        Console.WriteLine($"Protocol: {packetData.Protocol}");
        Console.WriteLine();
        
        for (var i = 0; i < packetData.ByteOffset.Length; i += 16)
        {
            int length = Math.Min(16, packetData.ByteOffset.Length - i);
            string hexLine = $"0x{i:X4}: ";
            string hexValues = BitConverter.ToString(packetData.ByteOffset, i, length).Replace('-', ' ');
            string asciiValues = Encoding.ASCII.GetString(packetData.ByteOffset, i, length)
                .Replace('\0', '.');
            Console.WriteLine($"{hexLine,-8}{hexValues,-48}{asciiValues}");
        }
        
        Console.WriteLine("--------------------------------------------");
        Console.WriteLine();
    }
}
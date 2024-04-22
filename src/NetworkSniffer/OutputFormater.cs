// Michal Balogh, xbalog06
// FIT VUT
// 2024

using System.Text;

namespace NetworkSniffer;

// Class that prints packet data in wireshark-like output to STDOUT
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
        
        // Hex dump of the packet data
        PrintHexDump(packetData.ByteOffset);
        
        Console.WriteLine("--------------------------------------------");
        Console.WriteLine();
    }
    
    private static void PrintHexDump(IEnumerable<byte> data)
    {
        const int bytesPerLine = 16;
        int byteCount = 0;
        var byteOffsetHexa = new StringBuilder();
        var byteOffsetAscii = new StringBuilder();

        foreach (byte b in data)
        {
            // Add byte and space in hex format
            byteOffsetHexa.Append(b.ToString("X2"));
            byteOffsetHexa.Append(' ');
                
            // Replace non printable characters with '.'
            byteOffsetAscii.Append(b is >= 32 and <= 126 ? (char)b : '.');
            
            byteCount++;
            
            // One line finished, print it and start new one
            if (byteCount % bytesPerLine == 0)
            {
                string byteOffset = $"0x{byteCount:X4}: ";
                Console.WriteLine($"{byteOffset}{byteOffsetHexa,-49}".ToLower() + $"{byteOffsetAscii}");
                byteOffsetHexa.Clear();
                byteOffsetAscii.Clear();
            }
            // Add extra line after 8 bytes in both hex and ascii part
            else if (byteCount % 8 == 0)
            {
                byteOffsetHexa.Append(' ');
                byteOffsetAscii.Append(' ');
            }
        }

        // Print remaining bytes 
        if (byteCount > 0)
        {
            // Round the byte offset to multiples of 16
            string byteOffset = $"0x{byteCount + bytesPerLine - byteCount % bytesPerLine:X4}: ";
            Console.WriteLine($"{byteOffset}{byteOffsetHexa,-49}".ToLower() + $"{byteOffsetAscii}");
        }
    }
}
// Michal Balogh, xbalog06
// FIT VUT
// 2024

using NetworkSniffer.Enums;
using SharpPcap;

namespace NetworkSniffer;

// Class for capturing packets
public class PacketCapture
{
    private readonly Options _options;
    private readonly ICaptureDevice _device = null!;
    private const int ReadTimeoutMilliseconds = 1000;

    public PacketCapture(Options options)
    {
        _options = options;
        
        // argument -i was used without value
        if (string.IsNullOrEmpty(options.Interface))
        {
            ListAllActiveInterfaces();
        }
        else
        {
            using var device = GetDevice(options.Interface);
            if (device == null)
            {
                ExitHandler.ExitFailure($"Interface '{options.Interface}' not found.", ExitCode.NoActiveInterfaces);
            }
            else
            {
                _device = device;
            }
            
            // Handle Ctrl+C
            Console.CancelKeyPress += OnCancelKeyPress;
        }
    }

    private static void ListAllActiveInterfaces()
    {
        if (CaptureDeviceList.Instance.Count < 1)
        {
            ExitHandler.ExitFailure("Error: No active interfaces found.", ExitCode.NoActiveInterfaces);
        }
        
        var devices = CaptureDeviceList.Instance;
        Console.WriteLine("Active interfaces:");
        foreach (var device in devices)
        {
            Console.WriteLine($"\t{device.Name}");
        }
        ExitHandler.ExitSuccess();
    }

    private static ICaptureDevice? GetDevice(string name)
    {
        // Try to find interface specified by user
        return CaptureDeviceList.Instance.FirstOrDefault(device => device.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    public void StartCapturing()
    {
        _device.OnPacketArrival += OnPacketArrival;

        _device.Open(DeviceModes.Promiscuous, ReadTimeoutMilliseconds);

        // Create capturing filter with options specified by user
        _device.Filter = Filter.Create(_options);
        
        _device.Capture();
    }

    private void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
    {
        // Clean up
        Console.WriteLine("Exiting...");
        Cleanup();
        ExitHandler.ExitSuccess();
    }
    
    private void OnPacketArrival(object sender, SharpPcap.PacketCapture e)
    {
        var time = GetTime();
        
        var rawPacket = e.GetPacket();

        PacketData? parsedPacket = PacketParser.Parse(rawPacket, _options);
        // Packet does not satisfy the filters
        if (parsedPacket == null)
        {
            return;
        }

        parsedPacket.Timestamp = time;
        // Print wireshark-like packet data to output
        OutputFormater.Output(parsedPacket);

        // If captured packet is equal to set parameter '-n', exit the program 
        if (--_options.PacketCount == 0)
        {
            Console.WriteLine("Packet count reached. Exiting...");
            Cleanup();
            ExitHandler.ExitSuccess();
        }
    }

    private string GetTime()
    {
        // Get time
        DateTimeOffset localTimeWithOffset = DateTimeOffset.Now;
        // Format it in RFC 3339 format
        string formattedTime = localTimeWithOffset.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz");
        return formattedTime;
    }
    
    private void Cleanup()
    {
        _device.Close();
    }
}
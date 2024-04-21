using NetworkSniffer.Enums;
using SharpPcap;

namespace NetworkSniffer;

public class PacketCapture
{
    private readonly Options _options;
    private readonly ICaptureDevice _device = null!;
    private const int ReadTimeoutMilliseconds = 1000;

    public PacketCapture(Options options)
    {
        _options = options;
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

    private ICaptureDevice? GetDevice(string name)
    {
        foreach (var device in CaptureDeviceList.Instance)
        {
            if (device.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return device;
            }
        }
        return null;
    }

    public void StartCapturing()
    {
        _device.OnPacketArrival += OnPacketArrival;

        _device.Open(DeviceModes.Promiscuous, ReadTimeoutMilliseconds);

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
        if (parsedPacket == null)
        {
            return;
        }

        parsedPacket.Timestamp = time;
        OutputFormater.Output(parsedPacket);

        if (--_options.PacketCount == 0)
        {
            Console.WriteLine("Packet count reached. Exiting...");
            Cleanup();
            ExitHandler.ExitSuccess();
        }
    }

    private string GetTime()
    {
        DateTimeOffset localTimeWithOffset = DateTimeOffset.Now;
        string formattedTime = localTimeWithOffset.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz");
        return formattedTime;
    }
    
    private void Cleanup()
    {
        _device.Close();
    }
}
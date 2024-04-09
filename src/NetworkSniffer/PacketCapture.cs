using System;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetworkSniffer;

public class PacketCapture
{
    private readonly Options _options;
    private bool _exit = false;
    private readonly ICaptureDevice _device = null!;

    public PacketCapture(Options options)
    {
        _options = options;
        if (string.IsNullOrEmpty(options.Interface))
        {
            var devices = CaptureDeviceList.Instance;
            Console.WriteLine("Active interfaces:");
            foreach (var dev in devices)
                Console.WriteLine($"\t{dev.Name}");
            ExitHandler.ExitSuccess();
        }
        else
        {
            using var device = GetDevice(options.Interface);
            if (device == null)
            {
                Console.WriteLine($"Interface '{options.Interface}' not found.");
                ExitHandler.ExitFailure();
            }
            else
            {
                _device = device;
            }
                
            Console.WriteLine($"Sniffing on interface {options.Interface}");
        }
        
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

    public void Start()
    {
        Console.CancelKeyPress += OnCancelKeyPress;
        
        _device.OnPacketArrival += OnPacketArrival;

        int readTimeoutMilliseconds = 1000;
        _device.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);

        _device.StartCapture();
        
        while (!_exit)
        {
            // Console.WriteLine("Sniffing...");
        }
    }

    private void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
    {
        // Clean up
        _device.StopCapture();
        Console.WriteLine("Exiting...");
        ExitHandler.ExitSuccess();
    }
    
    private void OnPacketArrival(object sender, SharpPcap.PacketCapture e)
    {
        var time = e.Header.Timeval.Date;
        var len = e.Data.Length;
        var rawPacket = e.GetPacket();
        Console.WriteLine("{0}:{1}:{2},{3} Len={4}",
            time.Hour, time.Minute, time.Second, time.Millisecond, len);
        Console.WriteLine(rawPacket.ToString());
    }
}
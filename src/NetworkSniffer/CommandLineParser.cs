using System;
using CommandLine;

namespace NetworkSniffer;

public class CommandLineParser
{
    public Options Parse(string[] args)
    {
        var options = new Options();
        var parser = new Parser(settings =>
        {
            settings.HelpWriter = null;
            settings.AutoHelp = false;
            settings.AutoVersion = false;
        });
        parser.ParseArguments<Options>(args)
            .WithParsed(o =>
            {
                if (o.Help)
                {
                    Console.WriteLine("Help message");
                    ExitHandler.ExitSuccess();
                }
                options = o;
            })
            .WithNotParsed(errors =>
            {

                foreach (var error in errors)
                {
                    if (error is MissingValueOptionError && args[0] == "-i" || args[0] == "--interface")
                    {
                        return;
                    }
                    ExitHandler.Warn(error.ToString());
                }
                ExitHandler.ExitFailure("Error while parsing command line arguments. Exiting.");
            });

        return options;
    }
}

public class Options
{
    [Option('i', "interface",
        HelpText = "Interface to sniff. If not specified, list of active interfaces is printed.")]
    public string? Interface { get; set; }

    [Option('t', "tcp", Required = false, HelpText = "Display TCP segments.")]
    public bool Tcp { get; set; }

    [Option('u', "udp", HelpText = "Display UDP datagrams.")]
    public bool Udp { get; set; }

    [Option('p', "port-source", HelpText = "Filter TCP/UDP based on source port number.")]
    public ushort PortSource { get; set; }

    [Option("port-destination", HelpText = "Filter TCP/UDP based on destination port number.")]
    public ushort PortDestination { get; set; }

    [Option('n', "num", HelpText = "Number of packets to display.")]
    public uint PacketCount { get; set; } = 1;
        
    [Option("icmp4", HelpText = "Display only ICMPv4 packets.")]
    public bool Icmp4 { get; set; }
        
    [Option("icmp6", HelpText = "Display only ICMPv6 echo request/response.")]
    public bool Icmp6 { get; set; }
        
    [Option("arp", HelpText = "Display only ARP frames.")]
    public bool Arp { get; set; }

    [Option("ndp", HelpText = "Display only NDP packets.")]
    public bool Ndp { get; set; }
        
    [Option("igmp", HelpText = "Display only IGMP packets.")]
    public bool Igmp { get; set; }

    [Option("mld", HelpText = "Display only MLD packets.")]
    public bool Mld { get; set; }

    [Option('h', "help", HelpText = "Display this help message.")]
    public bool Help { get; set; }
}
// Michal Balogh, xbalog06
// FIT VUT
// 2024

using CommandLine;

namespace NetworkSniffer;

// Class for handling user specified arguments
public class CommandLineParser
{
    public Options Parse(string[] args)
    {
        var options = new Options();
        var parser = new Parser(settings =>
        {
            // turn off default help message, if enabled, no value specified in interface parameter
            // results in error and printing the help message, which is not desired behaviour
            settings.HelpWriter = null;
            settings.AutoHelp = false;
            settings.AutoVersion = false;
        });
        parser.ParseArguments<Options>(args)
            .WithParsed(o =>
            {
                options = o;
            })
            .WithNotParsed(errors =>
            {
                // If error occurs, check if the error is missing value in interface parameter
                // If so, dont throw exception, rather set the flag, and return
                foreach (var error in errors)
                {
                    if (error is MissingValueOptionError && args[0] == "-i" || args[0] == "--interface")
                    {
                        return;
                    }
                    ExitHandler.Warn(error.ToString());
                }
                // Handle other errors
                throw new ArgumentException("Invalid arguments");
            });

        return options;
    }
}


// All options that can be specified by user
public class Options
{
    [Option('i', "interface",
        HelpText = "Interface to sniff. If not specified, list of active interfaces is printed.")]
    public string? Interface { get; set; }

    [Option('t', "tcp", Required = false, HelpText = "Display TCP segments.")]
    public bool Tcp { get; set; }

    [Option('u', "udp", HelpText = "Display UDP datagrams.")]
    public bool Udp { get; set; }

    [Option('p', HelpText = "Filter TCP/UDP based on port number")]
    public ushort? Port { get; set; }

    [Option("port-source", HelpText = "Filter TCP/UDP based on source port number.")]
    public ushort? PortSource { get; set; }

    [Option("port-destination", HelpText = "Filter TCP/UDP based on destination port number.")]
    public ushort? PortDestination { get; set; }

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
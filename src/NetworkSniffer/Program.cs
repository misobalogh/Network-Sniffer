// Michal Balogh, xbalog06
// FIT VUT
// 2024

namespace NetworkSniffer;

public static class Program
{
    private static void Main(string[] args)
    {
        var parser = new CommandLineParser();
       
        var options = parser.Parse(args);
        
        // Print help message if -h was used, or no args were specified
        if ((options.Help && args.Length == 1) || args.Length == 0)
        {
            PrintHelpMessage();
            ExitHandler.ExitSuccess();
        }
        
        // Instantiate new sniffer with set options
        var sniffer = new PacketCapture(options);
        sniffer.StartCapturing();
        
        ExitHandler.ExitSuccess();
    }

    private static void PrintHelpMessage()
    {
        Console.Error.Write("""

               Usage: ./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
               
               To stop capturing packets, press Ctrl+C
                
               Options:
                 -i, --interface   Specify the network interface to sniff packets from.
                                   If not specified, a list of active interfaces is printed.
                 -t, --tcp         Display TCP segments.
                 -u, --udp         Display UDP datagrams.
                 -p port           Filter TCP/UDP packets based on port number.
                 --port-destination port
                                   Filter TCP/UDP packets based on destination port number.
                 --port-source port
                                   Filter TCP/UDP packets based on source port number.
                 --icmp4           Display only ICMPv4 packets.
                 --icmp6           Display only ICMPv6 echo request/response packets.
                 --arp             Display only ARP frames.
                 --ndp             Display only NDP packets.
                 --igmp            Display only IGMP packets.
                 --mld             Display only MLD packets.
                 -n number         Specify the number of packets to catch. Default is 1.
               """);
    }
}

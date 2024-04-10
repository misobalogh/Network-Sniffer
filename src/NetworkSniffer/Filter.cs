using System.Text;

namespace NetworkSniffer;

public static class Filter
{
    public static string Create(Options options)
    {
        var filter = new StringBuilder();
        if (options.Tcp) filter.Append("tcp ");
        if (options.Udp) filter.Append("udp ");
        if (options.PortDestination != 0) filter.Append($"dst port {options.PortDestination} ");
        if (options.PortSource != 0) filter.Append($"src port {options.PortSource} ");
        if (options.Icmp4) filter.Append("icmp ");
        if (options.Icmp6) filter.Append("icmp6 ");
        if (options.Arp) filter.Append("arp ");
        if (options.Ndp) filter.Append("ndp ");
        if (options.Igmp) filter.Append("igmp ");
        if (options.Mld) filter.Append("mld ");

        return filter.ToString();
    }
    
} 
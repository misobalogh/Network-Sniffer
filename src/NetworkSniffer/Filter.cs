using System.Text;

namespace NetworkSniffer;

public static class Filter
{
    public static string Create(Options options)
    {
        var filter = new StringBuilder();
        if (options.Tcp) filter.Append("or tcp ");
        if (options.Udp) filter.Append("or udp ");
        if (options.PortDestination != 0) filter.Append($"dst port {options.PortDestination} ");
        if (options.PortSource != 0) filter.Append($"src port {options.PortSource} ");
        if (options.Icmp4) filter.Append("or icmp ");
        if (options.Icmp6) filter.Append("or icmp6 ");
        if (options.Arp) filter.Append("or arp ");
        if (options.Ndp) filter.Append("or ndp ");
        if (options.Igmp) filter.Append("or igmp ");
        if (options.Mld) filter.Append("or mld ");

        return filter.ToString();
    }
    
} 
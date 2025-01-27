// Michal Balogh, xbalog06
// FIT VUT
// 2024

using System.Text;

namespace NetworkSniffer;

// Class for building capturing filter from options set by user
public static class Filter
{
    private static bool _needConjunction = true;

    public static string Create(Options options)
    {
        var filter = new StringBuilder();
        if (options is { Tcp: true, Udp: true })
        {
            filter.Append("(tcp or udp) ");
        }
        else if (options.Tcp)
        {
            filter.Append("tcp ");
        }
        else if (options.Udp)
        {
            filter.Append("udp ");
        }
        else
        {
            _needConjunction = false;
        }

        // Ports are added only to tcp/udp packets
        if (options.Tcp || options.Udp)
        {
            // Port filters are exclusive, only one can be defined at a time 
            if (options.PortDestination != null) filter.Append($"and dst port {options.PortDestination} ");
            else if (options.PortSource != null) filter.Append($"and src port {options.PortSource} ");
            else if (options.Port != null) filter.Append($"and port {options.Port}");
        }

        
        if (options.Icmp4) filter.Append(AppendToFilter("icmp"));
        // There is no mld or ndp packet filter in pcap library, ndp and mld packets are handled in PacketParser class
        if (options.Icmp6 || options.Mld || options.Ndp) filter.Append(AppendToFilter("icmp6"));
        if (options.Arp) filter.Append(AppendToFilter("arp"));
        if (options.Igmp) filter.Append(AppendToFilter("igmp"));
        return filter.ToString();
    }

    // Adds the filter and also conjunction if needed
    private static string AppendToFilter(string name)
    {
        var stringToAppend = new StringBuilder();
        if (_needConjunction)
        {
            stringToAppend.Append("or ");
        }
        stringToAppend.Append(name + " ");
        
        _needConjunction = true;
        return stringToAppend.ToString();
    }
}
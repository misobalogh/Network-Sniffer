using System.Text;

namespace NetworkSniffer;

public static class Filter
{
    private static bool _needConjunction = false;

    public static string Create(Options options)
    {
        var filter = new StringBuilder();
        if (options.Tcp)
        {
            filter.Append("tcp ");
            _needConjunction = true;

        }

        if (options.Udp)
        {
            if (options.Tcp)
            {
                filter.Append("or ");
            }

            filter.Append("udp ");
            _needConjunction = true;
        }

        if (options.Tcp || options.Udp)
        {
            if (options.PortDestination != 0) filter.Append($"port {options.PortDestination} ");
            if (options.PortSource != 0) filter.Append($"port {options.PortSource} ");
        }

        
        if (options.Icmp4) filter.Append(AppendToFilter("icmp"));
        if (options.Icmp6 || options.Mld || options.Ndp) filter.Append(AppendToFilter("icmp6"));
        if (options.Arp) filter.Append(AppendToFilter("arp"));
        if (options.Igmp) filter.Append(AppendToFilter("igmp"));
        return filter.ToString();
    }

    private static string AppendToFilter(string name)
    {
        var stringToAppend = new StringBuilder();
        if (_needConjunction)
        {
            stringToAppend.Append("or ");
        }

        stringToAppend.Append(name + " ");
        
        return stringToAppend.ToString();
    }
}
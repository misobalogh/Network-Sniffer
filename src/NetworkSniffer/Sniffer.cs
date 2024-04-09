namespace NetworkSniffer;

public class Sniffer
{
    private readonly Options _options;

    public Sniffer(Options options)
    {
        _options = options;
        if (string.IsNullOrEmpty(options.Interface))
        {
            Console.WriteLine("List of active interfaces:");
        }
        else
        {
            Console.WriteLine($"Sniffing on interface {options.Interface}");
        }
        
    }
}
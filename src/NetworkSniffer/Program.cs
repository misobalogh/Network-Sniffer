namespace NetworkSniffer;

public static class Program
{
    static void Main(string[] args)
    {
        var parser = new CommandLineParser();
       
        var options = parser.Parse(args);
        
        var sniffer = new Sniffer(options);
        
    }
}
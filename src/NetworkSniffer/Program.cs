namespace NetworkSniffer;

public static class Program
{
    static void Main(string[] args)
    {
        var parser = new CommandLineParser();
       
        var options = parser.Parse(args);
        
        if ((options.Help && args.Length == 1) || args.Length == 0)
        {
            Console.Error.WriteLine("Help message");
            ExitHandler.ExitSuccess();
        }
        
        var sniffer = new PacketCapture(options);
        sniffer.StartCapturing();
        
        ExitHandler.ExitSuccess();
    }
}
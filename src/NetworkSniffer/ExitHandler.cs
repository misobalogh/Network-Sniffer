namespace NetworkSniffer;

public static class ExitHandler
{
    public static void ExitSuccess(string message="")
    {
        if (message != "")
        {
            Console.Error.WriteLine(message);
        }
        Environment.Exit(0);
    }
    
    public static void ExitFailure(string message="")
    {
        if (message != "")
        {
            Console.Error.WriteLine(message);
        }
        Environment.Exit(1);
    }
    
    public static void Warn(string? message)
    {
        Console.Error.WriteLine(message);
    }
}
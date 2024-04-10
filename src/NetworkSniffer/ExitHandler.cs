using NetworkSniffer.Enums;

namespace NetworkSniffer;


public static class ExitHandler
{
    public static void ExitSuccess(string message="", ExitCode code=ExitCode.Success)
    {
        if (message != "")
        {
            Console.Error.WriteLine(message);
        }
        Environment.Exit(0);
    }
    
    public static void ExitFailure(string message="", ExitCode code=ExitCode.Failure)
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
namespace NetworkSniffer.Enums;

public enum ExitCode
{
    Success = 0,
    Failure = 1,
    WrongParameter = 2,
    NoActiveInterfaces = 3,
    PacketParseError = 4
}
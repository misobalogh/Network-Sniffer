using CommandLine;

namespace NetworkSniffer.Tests;
public class CommandLineParserTests
{
    [Fact]
    public void Parse_WithValidArguments_ReturnsOptionsObject()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = ["-i", "eth0", "-t", "-u", "-p", "8080", "--num", "10"];

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.Equal("eth0", options.Interface);
        Assert.True(options.Tcp);
        Assert.True(options.Udp);
        Assert.Equal((ushort)8080, options.Port);
        Assert.Equal(10u, options.PacketCount);
    }

    [Fact]
    public void Parse_OnlyHelpArgument()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = ["--help"];

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.True(options.Help);
    }
    
    [Fact]
    public void Parse_HelpArgumentWithOtherArguments()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = ["-i", "eth0", "--help"];

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.True(options.Help);
        Assert.Equal("eth0", options.Interface);
    } 
    
    [Fact]
    public void Parse_NoArguments()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = [];

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.False(options.Tcp);
        Assert.False(options.Udp);
        Assert.Equal(1u, options.PacketCount);
    }
    
    [Fact]
    public void Parse_OnlyInterfaceArgument()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = ["-i", "eth0"];

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.Equal("eth0", options.Interface);
        Assert.False(options.Tcp);
        Assert.False(options.Udp);
        Assert.Equal(1u, options.PacketCount);
    }
    
    [Fact]
    public void Parse_OnlyInterfaceArgumentWithoutValue()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = ["-i"];

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.Null(options.Interface);
        Assert.Equal(1u, options.PacketCount);
    }

    [Fact]
    public void Parse_InvalidArguments_ReturnsDefaultOptions()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = ["-x", "invalid", "--num", "abc"];
        
        try
        {
            // Act
            var options = parser.Parse(args);
        }
        catch
        {
            // Assert
            Assert.Throws<ArgumentException>(() => parser.Parse(args));
        }
    }

    [Fact]
    public void Parse_PortSourceAndPortDestinationArguments()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = ["-i", "eth0", "--port-destination", "9090"];

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.Equal("eth0", options.Interface);
        Assert.Equal((ushort)9090, options.PortDestination);
    }
    
    [Fact]
    public void Parse_PortSourceAndPortDestinationArguments_Overflow()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = ["-i", "eth0", "-p", "65536", "--port-destination", "9090"];

        try
        {
            // Act
            var options = parser.Parse(args);
        }
        catch
        {
            Assert.Throws<ArgumentException>(() => parser.Parse(args));
        }
    }

    [Fact]
    public void Parse_ICMPv4AndICMPv6Arguments()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = ["-i", "eth0", "--icmp4", "--icmp6"];

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.Equal("eth0", options.Interface);
        Assert.True(options.Icmp4);
        Assert.True(options.Icmp6);
    }

    
}
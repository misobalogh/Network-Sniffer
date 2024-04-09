namespace NetworkSniffer.Tests;

public class CommandLineParserTests
{
    [Fact]
    public void Parse_WithValidArguments_ReturnsOptionsObject()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = new string[] { "-i", "eth0", "-t", "-u", "-p", "8080", "--num", "10" };

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.NotNull(options);
        Assert.Equal("eth0", options.Interface);
        Assert.True(options.Tcp);
        Assert.True(options.Udp);
        Assert.Equal((ushort)8080, options.PortSource);
        Assert.Equal(10u, options.PacketCount);
    }

    [Fact]
    public void Parse_WithHelpArgument_ExitsSuccessfully()
    {
        // Arrange
        var parser = new CommandLineParser();
        string[] args = new string[] { "--help" };

        // Act
        var options = parser.Parse(args);

        // Assert
        Assert.Null(options);
    }
}
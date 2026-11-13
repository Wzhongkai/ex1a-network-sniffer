using System.Net;

namespace Sniffer.Core;

public enum LinkType : uint
{
    Null = 0,
    Ethernet = 1,
    RawIp = 101
}

public sealed record RawPacket(DateTimeOffset Timestamp, LinkType Link, uint WireLength, byte[] Bytes);

public sealed record PacketField(string Name, string Value, int Offset, int Length)
{
    public string Label => $"{Name}  {Value}";
}

public sealed record PacketLayer(string Name, int Offset, int Length, IReadOnlyList<PacketField> Fields)
{
    public string Label => Name;
}

public sealed record DnsAddress(IPAddress Address, string Name);

public readonly record struct Endpoint(IPAddress Address, ushort Port)
{
    public override string ToString() => Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
        ? $"[{Address}]:{Port}"
        : $"{Address}:{Port}";
}

public sealed record TcpSegment(Endpoint Source, Endpoint Destination, uint Sequence, uint Acknowledgment,
    byte Flags, int PayloadOffset, int PayloadLength, bool PayloadTruncated)
{
    public bool Fin => (Flags & 1) != 0;
    public bool Syn => (Flags & 2) != 0;
    public bool Rst => (Flags & 4) != 0;
    public bool Ack => (Flags & 16) != 0;

    public string FlagNames => string.Join(" ", new[] { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR" }
        .Where((_, index) => (Flags & (1 << index)) != 0));
}

public sealed class Packet(long number, RawPacket raw)
{
    public long Number { get; } = number;
    public RawPacket Raw { get; } = raw;
    public int IpVersion { get; internal set; }
    public byte? IpProtocol { get; internal set; }
    public IPAddress? Source { get; internal set; }
    public IPAddress? Destination { get; internal set; }
    public ushort? SourcePort { get; internal set; }
    public ushort? DestinationPort { get; internal set; }
    public TcpSegment? Tcp { get; internal set; }
    public string? Http { get; internal set; }
    public string? Tls { get; internal set; }
    public string? Dns { get; internal set; }
    public IReadOnlyList<DnsAddress> DnsAddresses { get; internal set; } = [];
    public string? Note { get; internal set; }
    public string TransportSummary { get; internal set; } = "";
    public string LinkSummary { get; internal set; } = "";
    public long? FlowId { get; internal set; }
    internal FlowOwners? SessionOwners { get; set; }
    public IReadOnlyList<ProcessOwner> Owners => SessionOwners?.Snapshot ?? [];
    internal List<PacketLayer> DecodedLayers { get; } = [];
    public IReadOnlyList<PacketLayer> Layers => DecodedLayers;
    public string? SourceName { get; set; }
    public string? DestinationName { get; set; }
    public string? Color { get; set; }
    public string SourceText => AddressText(Source, SourcePort, SourceName);
    public string DestinationText => AddressText(Destination, DestinationPort, DestinationName);
    public string TimeText => Raw.Timestamp.ToLocalTime().ToString("HH:mm:ss.ffffff");
    public string Protocol => Http is not null ? "HTTP" : Tls is not null ? "TLS" : Dns is not null ? "DNS" : IpProtocol switch
    {
        6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6",
        _ => IpVersion > 0 ? $"IPv{IpVersion}" : LinkSummary
    };
    public string Info => string.Join(" · ", new[] { Http ?? Tls ?? Dns ?? TransportSummary, Note }
        .Where(value => !string.IsNullOrWhiteSpace(value)));
    public string ProcessText => string.Join(" / ", Owners.Select(owner => owner.Label).Distinct());

    private static string AddressText(IPAddress? address, ushort? port, string? name)
    {
        if (address is null) return "—";
        string numeric = port is ushort value ? new Endpoint(address, value).ToString() : address.ToString();
        return name is null ? numeric : $"{numeric} · {name}";
    }
}

public sealed record ProcessOwner(Endpoint Local, int Pid, string Name, DateTimeOffset? Started)
{
    public string Label => string.IsNullOrEmpty(Name) ? $"PID {Pid}" : $"{Name} ({Pid})";
}

internal sealed class FlowOwners
{
    private ProcessOwner[] _snapshot = [];
    public IReadOnlyList<ProcessOwner> Snapshot => Volatile.Read(ref _snapshot);
    public void Publish(ProcessOwner[] owners) => Volatile.Write(ref _snapshot, owners);
}

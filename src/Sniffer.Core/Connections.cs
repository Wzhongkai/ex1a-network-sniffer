using System.Net;

namespace Sniffer.Core;

public sealed record ConnectionRow(IPAddress Local, IPAddress Remote, string Direction, string LocalPorts,
    string RemotePorts, long Incoming, long Outgoing, long BytesIn, long BytesOut, int TcpFlows,
    string Protocols, string Processes, DateTimeOffset LastSeen)
{
    public string LastTime => LastSeen.ToLocalTime().ToString("HH:mm:ss.fff");
}

public static class Connections
{
    public static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4()
        : address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && address.ScopeId != 0
            ? new IPAddress(address.GetAddressBytes()) : address;

    public static IReadOnlyList<ConnectionRow> Summarize(IEnumerable<Packet> packets, IEnumerable<IPAddress> addresses)
    {
        var local = addresses.Select(Normalize).ToHashSet();
        var rows = new Dictionary<(IPAddress Local, IPAddress Remote, string Direction), Totals>();
        foreach (Packet packet in packets)
        {
            if (packet.Source is null || packet.Destination is null) continue;
            IPAddress source = Normalize(packet.Source);
            IPAddress destination = Normalize(packet.Destination);
            bool fromLocal = IPAddress.IsLoopback(source) || local.Contains(source) ||
                packet.Owners.Any(owner => Normalize(owner.Local.Address).Equals(source));
            bool toLocal = IPAddress.IsLoopback(destination) || local.Contains(destination) ||
                packet.Owners.Any(owner => Normalize(owner.Local.Address).Equals(destination));
            bool outgoing = fromLocal != toLocal ? fromLocal : Compare(source, destination) < 0 ||
                source.Equals(destination) && (packet.SourcePort ?? 0) <= (packet.DestinationPort ?? 0);
            var key = outgoing ? (source, destination, Scope(fromLocal, toLocal)) : (destination, source, Scope(fromLocal, toLocal));
            if (!rows.TryGetValue(key, out Totals? totals)) rows.Add(key, totals = new());
            totals.Add(packet, outgoing);
        }

        return rows.Select(row => row.Value.Build(row.Key.Local, row.Key.Remote, row.Key.Direction))
            .OrderByDescending(row => row.LastSeen).ToArray();
    }

    private static int Compare(IPAddress a, IPAddress b) =>
        a.GetAddressBytes().AsSpan().SequenceCompareTo(b.GetAddressBytes());

    private static string Scope(bool a, bool b) => a && b ? "本机双端" : a || b ? "本机 ↔ 远端" : "旁路 A ↔ B";

    private sealed class Totals
    {
        private readonly SortedSet<ushort> _localPorts = [];
        private readonly SortedSet<ushort> _remotePorts = [];
        private readonly HashSet<long> _flows = [];
        private readonly SortedSet<string> _protocols = [];
        private readonly SortedSet<string> _processes = [];
        private long _incoming, _outgoing, _bytesIn, _bytesOut;
        private DateTimeOffset _last;

        public void Add(Packet packet, bool outgoing)
        {
            if ((outgoing ? packet.SourcePort : packet.DestinationPort) is ushort local) _localPorts.Add(local);
            if ((outgoing ? packet.DestinationPort : packet.SourcePort) is ushort remote) _remotePorts.Add(remote);
            if (packet.FlowId is long flow) _flows.Add(flow);
            _protocols.Add(packet.Protocol);
            foreach (ProcessOwner process in packet.Owners) _processes.Add(process.Label);
            if (outgoing) { _outgoing++; _bytesOut += packet.Raw.WireLength; }
            else { _incoming++; _bytesIn += packet.Raw.WireLength; }
            if (packet.Raw.Timestamp > _last) _last = packet.Raw.Timestamp;
        }

        public ConnectionRow Build(IPAddress local, IPAddress remote, string scope) =>
            new(local, remote, scope, string.Join(", ", _localPorts), string.Join(", ", _remotePorts),
                _incoming, _outgoing, _bytesIn, _bytesOut, _flows.Count, string.Join(", ", _protocols),
                string.Join(", ", _processes), _last);
    }
}

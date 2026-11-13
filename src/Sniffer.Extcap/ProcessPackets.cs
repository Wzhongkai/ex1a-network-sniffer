using Sniffer.Core;

namespace Sniffer.Extcap;

internal sealed class ProcessPackets(int pid, Action<RawPacket> write)
{
    private const int MaxFlows = 512;
    private const int MaxPendingPackets = 16;
    private static readonly TimeSpan PendingWindow = TimeSpan.FromSeconds(1);
    private readonly Dictionary<long, PendingFlow> _flows = [];
    private readonly Queue<long> _order = new();

    public void Accept(Packet packet)
    {
        if (packet.FlowId is not long flowId) return;
        if (!_flows.TryGetValue(flowId, out PendingFlow? flow))
        {
            flow = new PendingFlow(packet.Raw.Timestamp);
            _flows.Add(flowId, flow);
            _order.Enqueue(flowId);
            if (_order.Count > MaxFlows) _flows.Remove(_order.Dequeue());
        }

        if (flow.Matched)
        {
            write(packet.Raw);
            return;
        }

        // The connection can become visible in the TCP table after its first packets arrive.
        if (packet.Raw.Timestamp - flow.First > PendingWindow)
        {
            flow.Pending.Clear();
            flow.LastPending = null;
        }
        if (Match(flow, packet.Owners))
        {
            write(packet.Raw);
        }
        else if (flow.Pending.Count < MaxPendingPackets && packet.Raw.Timestamp - flow.First <= PendingWindow)
        {
            flow.Pending.Add(packet.Raw);
            flow.LastPending = packet;
        }
    }

    public bool FlushNewOwners()
    {
        bool matched = false;
        foreach (PendingFlow flow in _flows.Values)
            if (!flow.Matched && flow.LastPending is { } packet)
                matched |= Match(flow, packet.Owners);
        return matched;
    }

    private bool Match(PendingFlow flow, IReadOnlyList<ProcessOwner> owners)
    {
        if (!owners.Any(owner => owner.Pid == pid)) return false;
        flow.Matched = true;
        foreach (RawPacket earlier in flow.Pending) write(earlier);
        flow.Pending.Clear();
        flow.LastPending = null;
        return true;
    }

    private sealed class PendingFlow(DateTimeOffset first)
    {
        public DateTimeOffset First { get; } = first;
        public bool Matched { get; set; }
        public List<RawPacket> Pending { get; } = [];
        public Packet? LastPending { get; set; }
    }
}

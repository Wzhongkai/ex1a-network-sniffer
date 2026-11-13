using Sniffer.Core;
using System.ComponentModel;
using System.Diagnostics;

namespace Sniffer.Windows;

public sealed class LiveAnalysis
{
    private readonly TcpOwners _owners = new();
    private readonly object _gate = new();
    private readonly Dictionary<(Endpoint, Endpoint), ObservedSocket> _sockets = [];
    private long _number;
    public FlowTracker Flows { get; } = new();

    public Packet Decode(RawPacket raw, bool live)
    {
        Packet packet = PacketDecoder.Decode(++_number, raw);
        Observe(packet, live);
        return packet;
    }

    public void Observe(Packet packet, bool live)
    {
        if (!live || packet.Tcp is not { } tcp) { Flows.Observe(packet); return; }
        var owners = _owners.Resolve(tcp, packet.Raw.Timestamp).ToList();
        lock (_gate)
        {
            AddSocketOwner(owners, tcp.Source, tcp.Destination, packet.Raw.Timestamp);
            AddSocketOwner(owners, tcp.Destination, tcp.Source, packet.Raw.Timestamp);
            Flows.Observe(packet, owners);
        }
    }

    public string? SocketEventsUnavailable { get; private set; }

    public IDisposable? TrackSockets()
    {
        DivertSession session;
        try { session = DivertSession.Open("tcp", DivertSession.Layer.Flow); }
        catch (Exception error) when (error is NotSupportedException or Win32Exception)
        {
            SocketEventsUnavailable = error.Message;
            return null;
        }
        return new SocketWatcher(session, ObserveSocket, error => SocketEventsUnavailable = error.Message);
    }

    private void AddSocketOwner(List<ProcessOwner> owners, Endpoint local, Endpoint remote, DateTimeOffset timestamp)
    {
        if (_sockets.TryGetValue((local, remote), out ObservedSocket? observed) &&
            observed.Opened <= timestamp.AddMilliseconds(100) && !(observed.Closed < timestamp.AddMilliseconds(-250)))
        {
            owners.RemoveAll(owner => owner.Local == local);
            owners.Add(observed.Owner);
        }
    }

    private void ObserveSocket(Endpoint local, Endpoint remote, int pid, bool closed, DateTimeOffset timestamp)
    {
        ProcessOwner owner = new(local, pid, "", null);
        if (!closed)
        {
            try
            {
                using Process process = Process.GetProcessById(pid);
                owner = owner with { Name = process.ProcessName };
            }
            catch (Exception error) when (error is ArgumentException or InvalidOperationException or Win32Exception) { }
        }
        lock (_gate)
        {
            var key = (local, remote);
            if (closed)
            {
                if (_sockets.TryGetValue(key, out ObservedSocket? socket) && socket.Owner.Pid == pid)
                    _sockets[key] = socket with { Closed = timestamp };
                return;
            }
            // Loopback can report multiple flow establishments for the same live endpoint pair.
            // The first event identifies the original endpoint before any subsequent notifications.
            if (_sockets.TryGetValue(key, out ObservedSocket? previous) && previous.Closed is null)
                return;
            if (_sockets.Count >= 8192)
            {
                foreach (var expired in _sockets.Where(pair => pair.Value.Closed.HasValue).Take(1024).ToArray())
                    _sockets.Remove(expired.Key);
                if (_sockets.Count >= 8192) _sockets.Remove(_sockets.First().Key);
            }
            _sockets[key] = new ObservedSocket(owner, timestamp, null);
            Flows.AssociateOwner(owner, remote, timestamp);
        }
    }

    private sealed record ObservedSocket(ProcessOwner Owner, DateTimeOffset Opened, DateTimeOffset? Closed);

    private sealed class SocketWatcher : IDisposable
    {
        private readonly CancellationTokenSource _stop = new();
        private readonly DivertSession _session;
        private readonly Task _reader;

        public SocketWatcher(DivertSession session, Action<Endpoint, Endpoint, int, bool, DateTimeOffset> receive,
            Action<Win32Exception> onError)
        {
            _session = session;
            _reader = Task.Factory.StartNew(() =>
            {
                try { _session.ObserveFlows(receive, _stop.Token); }
                catch (Win32Exception error) { onError(error); }
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        public void Dispose()
        {
            _stop.Cancel();
            _session.Stop();
            try { _reader.GetAwaiter().GetResult(); }
            finally { _session.Dispose(); _stop.Dispose(); }
        }
    }
}

using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Sniffer.Core;

namespace Sniffer.Windows;

public sealed class TcpOwners
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int OwnerPidConnections = 4;
    private const uint InsufficientBuffer = 122;
    private readonly Dictionary<(Endpoint, Endpoint), int> _endpoints = [];
    private readonly Dictionary<int, (string Name, DateTimeOffset? Started)> _processes = [];
    private long _nextRefresh;
    private DateTimeOffset _snapshot;

    public IReadOnlyList<ProcessOwner> Resolve(TcpSegment segment, DateTimeOffset timestamp)
    {
        long now = Environment.TickCount64;
        if (now >= _nextRefresh)
        {
            _endpoints.Clear();
            _processes.Clear();
            ReadTable(AfInet);
            ReadTable(AfInet6);
            _snapshot = DateTimeOffset.UtcNow;
            _nextRefresh = now + 120;
        }
        if ((_snapshot - timestamp).Duration() > TimeSpan.FromSeconds(2)) return [];

        ProcessOwner? source = Find(segment.Source, segment.Destination, timestamp);
        ProcessOwner? destination = Find(segment.Destination, segment.Source, timestamp);
        if (source is not null && destination is not null && source.Local != destination.Local)
            return [source, destination];
        if (source is not null) return [source];
        return destination is not null ? [destination] : [];
    }

    private ProcessOwner? Find(Endpoint local, Endpoint remote, DateTimeOffset timestamp)
    {
        if (!_endpoints.TryGetValue((local, remote), out int pid) || pid <= 0)
            return null;
        if (!_processes.TryGetValue(pid, out var process))
        {
            try
            {
                using var handle = Process.GetProcessById(pid);
                string name = handle.ProcessName;
                DateTimeOffset? started = null;
                try { started = handle.StartTime.ToUniversalTime(); }
                catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
                process = (name, started);
            }
            catch (Exception error) when (error is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                process = ("", null);
            }
            _processes[pid] = process;
        }
        return process.Started > timestamp ? null : new ProcessOwner(local, pid, process.Name, process.Started);
    }

    private void ReadTable(int family)
    {
        int size = 0;
        uint result = GetExtendedTcpTable(null, ref size, false, family, OwnerPidConnections, 0);
        for (int attempt = 0; result == InsufficientBuffer && attempt < 3; attempt++)
        {
            if (size < 4 || size > 8 * 1024 * 1024) return;
            var table = new byte[size];
            result = GetExtendedTcpTable(table, ref size, false, family, OwnerPidConnections, 0);
            if (result != 0) continue;
            int rowLength = family == AfInet ? 24 : 56;
            int count = BinaryPrimitives.ReadInt32LittleEndian(table);
            if (count < 0 || count > (table.Length - 4) / rowLength) return;
            for (int row = 0; row < count; row++)
                ReadRow(table.AsSpan(4 + row * rowLength, rowLength), family);
        }
    }

    private void ReadRow(ReadOnlySpan<byte> row, int family)
    {
        var local = family == AfInet ? EndpointAt(row, 4, 8, 4) : EndpointAt(row, 0, 20, 16);
        var remote = family == AfInet ? EndpointAt(row, 12, 16, 4) : EndpointAt(row, 24, 44, 16);
        int pid = BinaryPrimitives.ReadInt32LittleEndian(row[^4..]);
        if (pid <= 0 || local.Port == 0 || remote.Port == 0) return;
        var key = (local, remote);
        if (!_endpoints.TryAdd(key, pid) && _endpoints[key] != pid)
            _endpoints[key] = 0;
    }

    private static Endpoint EndpointAt(ReadOnlySpan<byte> row, int address, int port, int width)
    {
        IPAddress ip = new(row.Slice(address, width));
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return new Endpoint(ip, BinaryPrimitives.ReadUInt16BigEndian(row[port..]));
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedTcpTable([Out] byte[]? table, ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, uint reserved);
}

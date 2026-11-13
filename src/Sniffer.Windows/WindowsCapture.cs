using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Sniffer.Core;

namespace Sniffer.Windows;

public sealed record CaptureInterface(string Id, string Name, bool Loopback, LinkType Link, string? AdapterId = null)
{
    public override string ToString() => Name;
}

public readonly record struct CaptureStatistics(long Received, long? Dropped);

public sealed class WindowsCapture(CaptureInterface item, string filter)
{
    public const string Version = "Windows Packet Monitor + Winsock + WinDivert";
    private const string LoopbackId = "loopback-v4";
    private const string Loopback6Id = "loopback-v6";
    private static readonly CaptureInterface Loopback = new(LoopbackId, "Loopback · 本机 IPv4 回环", true, LinkType.RawIp);
    private static readonly CaptureInterface Loopback6 = new(Loopback6Id, "Loopback · 本机 IPv6 回环", true, LinkType.RawIp);
    private readonly Func<Packet, bool> _filter = DisplayFilter.CompileCapture(filter);
    public LinkType Link => item.Link;

    public static IReadOnlyList<CaptureInterface> Interfaces()
    {
        using var monitor = new PacketMonitorSession();
        return [Loopback, Loopback6, .. monitor.Interfaces()];
    }

    public static IReadOnlyList<CaptureInterface> PreviewInterfaces() =>
        [Loopback, Loopback6, .. NetworkInterface.GetAllNetworkInterfaces()
            .Where(adapter => adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                adapter.OperationalStatus == OperationalStatus.Up)
            .OrderBy(adapter => adapter.Name)
            .Select(adapter => new CaptureInterface(adapter.Id, $"{adapter.Name} · {adapter.Description}", false,
                adapter.NetworkInterfaceType == NetworkInterfaceType.Tunnel ? LinkType.RawIp : LinkType.Ethernet, adapter.Id))];

    public void Run(Action<Packet> receive, Action<CaptureStatistics> statistics, CancellationToken cancellation,
        Action? started = null)
    {
        long received = 0;
        long delivered = 0;
        void ReadPacket(RawPacket raw)
        {
            received++;
            Packet packet = PacketDecoder.Decode(delivered + 1, raw);
            if (!_filter(packet)) return;
            delivered++;
            receive(packet);
        }

        if (item.Id == Loopback6Id)
        {
            using var divert = DivertSession.Open("ipv6 and loopback", DivertSession.Layer.Network);
            using var stop = cancellation.Register(divert.Stop);
            started?.Invoke();
            divert.Capture(ReadPacket, cancellation);
            statistics(new CaptureStatistics(received, null));
            return;
        }

        if (item.Loopback)
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(3), null);
            socket.ReceiveTimeout = 150;
            var buffer = new byte[65_535];
            started?.Invoke();
            while (!cancellation.IsCancellationRequested)
            {
                int length;
                try { length = socket.Receive(buffer); }
                catch (SocketException exception) when (exception.SocketErrorCode == SocketError.TimedOut) { continue; }

                if (length > 0)
                    ReadPacket(new RawPacket(DateTimeOffset.UtcNow, Link, (uint)length, buffer[..length]));
            }
            statistics(new CaptureStatistics(received, null));
            return;
        }

        using var monitor = new PacketMonitorSession();
        monitor.Run(item, ReadPacket, dropped => statistics(new CaptureStatistics(received, dropped)), cancellation, started);
    }
}

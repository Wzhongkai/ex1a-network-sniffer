using System.Globalization;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Sniffer.Core;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace Sniffer.Windows;

internal sealed class PacketMonitorSession : IDisposable
{
    private const int ApiVersion = 0x00010000;
    private const int NetworkAdapter = 1;
    private const int PacketMetadataSize = 40;
    private const int SnapshotSize = 9000;
    private readonly IntPtr _monitor;

    public PacketMonitorSession()
    {
        try { Check(Native.PacketMonitorInitialize(ApiVersion, IntPtr.Zero, out _monitor), "初始化 Windows 抓包"); }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
            throw new NotSupportedException("此 Windows 版本缺少 Packet Monitor 实时接口。", error);
        }
    }

    public IReadOnlyList<CaptureInterface> Interfaces()
    {
        var adapters = NetworkInterface.GetAllNetworkInterfaces();
        return WithSources(sources => sources.Where(source => source.Data.Kind == NetworkAdapter)
            .Select(source =>
            {
                DataSource data = source.Data;
                var adapter = adapters.FirstOrDefault(nic => Guid.TryParse(nic.Id, out Guid id) &&
                    (data.Flags & 1) != 0 && id == data.Guid);
                if (adapter is null)
                {
                    var byDescription = adapters.Where(nic => nic.Description.Equals(data.Description,
                        StringComparison.OrdinalIgnoreCase)).Take(2).ToArray();
                    if (byDescription.Length == 1) adapter = byDescription[0];
                }
                string name = adapter is null ? data.Description : $"{adapter.Name} · {data.Description}";
                bool ipTunnel = adapter?.NetworkInterfaceType == NetworkInterfaceType.Tunnel ||
                    data.Name.Equals("wintun.sys", StringComparison.OrdinalIgnoreCase);
                return new CaptureInterface(data.Id.ToString(CultureInfo.InvariantCulture), name, false,
                    ipTunnel ? LinkType.RawIp : LinkType.Ethernet, adapter?.Id);
            }).OrderBy(item => item.Name).ToArray());
    }

    public void Run(CaptureInterface item, Action<RawPacket> receive, Action<long> statistics,
        CancellationToken cancellation, Action? started)
    {
        IntPtr session = IntPtr.Zero;
        IntPtr stream = IntPtr.Zero;
        var queue = Channel.CreateBounded<RawPacket>(new BoundedChannelOptions(2048) { SingleReader = true });
        long lost = 0;
        bool active = false;
        int payloadType = item.Link == LinkType.RawIp ? 3 : 1;
        DataCallback data = (IntPtr _, in StreamPacket descriptor) =>
        {
            Interlocked.Add(ref lost, (long)descriptor.WriteLoss + descriptor.ReadLoss);
            if (cancellation.IsCancellationRequested) return;
            try
            {
                // System timestamps are FILETIME ticks. Offsets are relative to the descriptor's buffer.
                if (descriptor.Data == IntPtr.Zero || descriptor.PacketLength is 0 or > SnapshotSize ||
                    descriptor.MetadataOffset > descriptor.DataSize || descriptor.DataSize - descriptor.MetadataOffset < PacketMetadataSize ||
                    descriptor.PacketOffset > descriptor.DataSize || descriptor.DataSize - descriptor.PacketOffset < descriptor.PacketLength)
                    return;
                IntPtr metadata = IntPtr.Add(descriptor.Data, checked((int)descriptor.MetadataOffset));
                if (Marshal.ReadInt16(metadata, 14) != payloadType) return;
                var bytes = new byte[descriptor.PacketLength];
                Marshal.Copy(IntPtr.Add(descriptor.Data, checked((int)descriptor.PacketOffset)), bytes, 0, bytes.Length);
                var timestamp = DateTimeOffset.FromFileTime(Marshal.ReadInt64(metadata, 32)).ToUniversalTime();
                if (!queue.Writer.TryWrite(new RawPacket(timestamp, item.Link, (uint)bytes.Length, bytes)))
                    Interlocked.Increment(ref lost);
            }
            catch (Exception error) { queue.Writer.TryComplete(error); }
        };
        EventCallback events = (_, info, kind) =>
        {
            if (kind == 2)
            {
                int reason = info == IntPtr.Zero ? 0 : Marshal.ReadInt32(info, 4);
                queue.Writer.TryComplete(new IOException($"Windows 抓包流异常（{reason}）。"));
            }
        };

        try
        {
            Check(Native.PacketMonitorCreateLiveSession(_monitor, $"Sniffer {Environment.ProcessId} {Guid.NewGuid():N}", out session),
                "创建捕获会话");
            WithSources(sources =>
            {
                uint id = uint.Parse(item.Id, CultureInfo.InvariantCulture);
                Source? adapter = sources.FirstOrDefault(source => source.Data.Kind == NetworkAdapter && source.Data.Id == id);
                if (adapter is null) throw new IOException("所选网卡已不可用，请刷新接口列表。");
                // Capture Ethernet frames at the 802.3 edge for native Wi-Fi adapters.
                Source selected = sources.FirstOrDefault(source => source.Data.ParentId == id &&
                    source.Data.Description.Equals("WFP 802.3 Filter", StringComparison.OrdinalIgnoreCase)) ?? adapter;
                Check(Native.PacketMonitorAddSingleDataSourceToSession(session, selected.Pointer), "选择捕获接口");
                return true;
            });

            var config = new StreamConfiguration { Event = events, Data = data, BufferMultiplier = 8, SnapshotSize = SnapshotSize };
            Check(Native.PacketMonitorCreateRealtimeStream(_monitor, ref config, out stream), "打开实时数据流");
            Check(Native.PacketMonitorAttachOutputToSession(session, stream), "绑定实时数据流");
            cancellation.ThrowIfCancellationRequested();
            Check(Native.PacketMonitorSetSessionActive(session, 1), "启动捕获");
            active = true;
            started?.Invoke();

            long nextStats = 0;
            try
            {
                while (queue.Reader.WaitToReadAsync(cancellation).AsTask().GetAwaiter().GetResult())
                {
                    while (!cancellation.IsCancellationRequested && queue.Reader.TryRead(out RawPacket? packet))
                        receive(packet);
                    if (Environment.TickCount64 >= nextStats)
                    {
                        statistics(Interlocked.Read(ref lost));
                        nextStats = Environment.TickCount64 + 500;
                    }
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        }
        finally
        {
            if (active) Native.PacketMonitorSetSessionActive(session, 0);
            if (stream != IntPtr.Zero) Native.PacketMonitorCloseRealtimeStream(stream);
            if (session != IntPtr.Zero) Native.PacketMonitorCloseSessionHandle(session);
            GC.KeepAlive(data);
            GC.KeepAlive(events);
            statistics(Interlocked.Read(ref lost));
        }
    }

    private T WithSources<T>(Func<IReadOnlyList<Source>, T> action)
    {
        int status = Native.PacketMonitorEnumDataSources(_monitor, 0, 0, 0, out nuint capacity, IntPtr.Zero);
        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (status != unchecked((int)0x8007007a)) Check(status, "获取接口列表大小");
            if (capacity < 8 || capacity > 8 * 1024 * 1024)
                throw new IOException("Windows 报告了无效的接口列表大小。");
            IntPtr memory = Marshal.AllocHGlobal((int)capacity);
            try
            {
                status = Native.PacketMonitorEnumDataSources(_monitor, 0, 0, capacity, out nuint required, memory);
                if (status == unchecked((int)0x8007007a) && required > capacity)
                {
                    capacity = required;
                    continue;
                }
                Check(status, "枚举捕获接口");
                int count = Marshal.ReadInt32(memory);
                if (count < 0 || (nuint)(8L + 8L * count) > capacity)
                    throw new IOException("Windows 返回了无效的接口数量。");
                var sources = new List<Source>(count);
                int sourceSize = Marshal.SizeOf<DataSource>();
                for (int i = 0; i < count; i++)
                {
                    IntPtr entry = Marshal.ReadIntPtr(memory, 8 + i * 8);
                    long offset = entry.ToInt64() - memory.ToInt64();
                    if (offset < 0 || (ulong)offset + (uint)sourceSize > capacity)
                        throw new IOException("Windows 返回了无效的接口描述。");
                    sources.Add(new Source(entry, Marshal.PtrToStructure<DataSource>(entry)));
                }
                return action(sources);
            }
            finally { Marshal.FreeHGlobal(memory); }
        }
        throw new IOException("接口列表正在变化，请刷新后重试。");
    }

    public void Dispose() => Native.PacketMonitorUninitialize(_monitor);

    private static void Check(int result, string operation)
    {
        if (result >= 0) return;
        if (result == unchecked((int)0x80070005))
            throw new UnauthorizedAccessException("实时抓包需要 Windows 管理员权限。请右键程序，选择「以管理员身份运行」。");
        throw new IOException($"{operation}失败（0x{result:X8}）：{Marshal.GetExceptionForHR(result)?.Message}");
    }

    private sealed record Source(IntPtr Pointer, DataSource Data);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DataSource
    {
        public uint Kind;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string Name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Description;
        public uint Id, SecondaryId, ParentId, Flags;
        public Guid Guid;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void DataCallback(IntPtr context, in StreamPacket packet);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void EventCallback(IntPtr context, IntPtr info, int kind);

    [StructLayout(LayoutKind.Sequential)]
    private struct StreamConfiguration
    {
        public IntPtr Context;
        public EventCallback Event;
        public DataCallback Data;
        public ushort BufferMultiplier, SnapshotSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StreamPacket
    {
        public IntPtr Data;
        public uint DataSize, MetadataOffset, PacketOffset, PacketLength, WriteLoss, ReadLoss;
    }

    private static class Native
    {
        private const string Dll = "PktMonApi.dll";
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int PacketMonitorInitialize(uint version, IntPtr reserved, out IntPtr handle);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern void PacketMonitorUninitialize(IntPtr handle);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int PacketMonitorEnumDataSources(IntPtr handle, uint kind, byte hidden, nuint capacity,
            out nuint needed, IntPtr list);
        [DllImport(Dll, ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern int PacketMonitorCreateLiveSession(IntPtr handle, string name, out IntPtr session);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern void PacketMonitorCloseSessionHandle(IntPtr session);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int PacketMonitorAddSingleDataSourceToSession(IntPtr session, IntPtr source);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int PacketMonitorCreateRealtimeStream(IntPtr handle, ref StreamConfiguration config, out IntPtr stream);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern void PacketMonitorCloseRealtimeStream(IntPtr stream);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int PacketMonitorAttachOutputToSession(IntPtr session, IntPtr output);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int PacketMonitorSetSessionActive(IntPtr session, byte active);
    }
}

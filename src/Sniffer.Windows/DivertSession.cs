using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Sniffer.Core;

namespace Sniffer.Windows;

internal sealed class DivertSession : IDisposable
{
    internal enum Layer { Network, Flow = 2 }
    private const ulong SniffAndReceiveOnly = 5;
    private const int ShutdownReceive = 1;
    private const int NoData = 232;
    private const int OperationAborted = 995;
    private readonly IntPtr _handle;
    private readonly byte[] _address = new byte[80];
    private readonly long _clockStart = Stopwatch.GetTimestamp();
    private readonly DateTimeOffset _utcStart = DateTimeOffset.UtcNow;
    private DateTimeOffset EventTime => _utcStart + Stopwatch.GetElapsedTime(_clockStart,
        BinaryPrimitives.ReadInt64LittleEndian(_address));

    static DivertSession()
    {
        NativeLibrary.SetDllImportResolver(typeof(DivertSession).Assembly, (name, _, _) => name == Dll
            ? NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, Dll)) : IntPtr.Zero);
    }

    private DivertSession(IntPtr handle) => _handle = handle;

    internal static DivertSession Open(string filter, Layer layer)
    {
        IntPtr handle;
        try { handle = WinDivertOpen(filter, layer, 0, SniffAndReceiveOnly); }
        catch (Exception error) when (error is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException)
        {
            throw new NotSupportedException("无法载入发布包附带的 WinDivert 组件。", error);
        }
        if (handle == new IntPtr(-1))
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"WinDivert 无法启动，系统错误 {Marshal.GetLastPInvokeError()}。");
        return new DivertSession(handle);
    }

    internal void Capture(Action<RawPacket> receive, CancellationToken token)
    {
        var buffer = new byte[65_575];
        while (!token.IsCancellationRequested && Receive(buffer, out uint size, token))
            if (size > 0)
                receive(new RawPacket(EventTime, LinkType.RawIp, size, buffer[..(int)size]));
    }

    internal void ObserveFlows(Action<Endpoint, Endpoint, int, bool, DateTimeOffset> receive, CancellationToken token)
    {
        while (!token.IsCancellationRequested && Receive(null, out _, token))
        {
            int pid = BinaryPrimitives.ReadInt32LittleEndian(_address.AsSpan(32));
            if (pid <= 0) continue;
            var local = new Endpoint(ReadAddress(36), BinaryPrimitives.ReadUInt16LittleEndian(_address.AsSpan(68)));
            var remote = new Endpoint(ReadAddress(52), BinaryPrimitives.ReadUInt16LittleEndian(_address.AsSpan(70)));
            if (local.Port > 0 && remote.Port > 0)
                receive(local, remote, pid, _address[9] == 2, EventTime);
        }
    }

    private IPAddress ReadAddress(int offset)
    {
        Span<byte> ip = stackalloc byte[16];
        for (int i = 0; i < 4; i++)
        {
            uint word = BinaryPrimitives.ReadUInt32LittleEndian(_address.AsSpan(offset + i * 4));
            BinaryPrimitives.WriteUInt32BigEndian(ip[((3 - i) * 4)..], word);
        }
        return Connections.Normalize(new IPAddress(ip));
    }

    private bool Receive(byte[]? data, out uint size, CancellationToken token)
    {
        if (WinDivertRecv(_handle, data, (uint)(data?.Length ?? 0), out size, _address)) return true;
        int error = Marshal.GetLastPInvokeError();
        if (token.IsCancellationRequested && error is NoData or OperationAborted) return false;
        throw new Win32Exception(error);
    }

    internal void Stop() => WinDivertShutdown(_handle, ShutdownReceive);
    public void Dispose() => WinDivertClose(_handle);

    private const string Dll = "WinDivert.dll";

    [DllImport(Dll, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory)]
    private static extern IntPtr WinDivertOpen([MarshalAs(UnmanagedType.LPStr)] string filter, Layer layer, short priority, ulong flags);

    [DllImport(Dll, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertRecv(IntPtr handle, [Out] byte[]? packet, uint length, out uint read, [Out] byte[] address);

    [DllImport(Dll, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertShutdown(IntPtr handle, int mode);

    [DllImport(Dll, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertClose(IntPtr handle);
}

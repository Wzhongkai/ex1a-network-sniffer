using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Sniffer.Core;
using Sniffer.Windows;

internal static class CaptureBenchmark
{
    private const int Batches = 150;
    private const int PerBatch = 20;
    private const int IntervalMs = 20;
    private const int PayloadSize = 128;

    public static async Task Run(string mode)
    {
        if (mode is not ("none" or "display" or "capture"))
            throw new ArgumentException("Benchmark mode must be none, display or capture.");

        using var target = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var control = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int targetPort = ((IPEndPoint)target.Client.LocalEndPoint!).Port;
        int controlPort = ((IPEndPoint)control.Client.LocalEndPoint!).Port;
        string scoped = $"udp and (dst port {targetPort} or dst port {controlPort})";
        string filter = mode == "capture" ? $"udp and dst port {targetPort}" : scoped;
        Func<Packet, bool> display = DisplayFilter.Compile(mode == "display" ? $"udp && dstport == {targetPort}" : "");
        var item = WindowsCapture.Interfaces().Single(nic => nic.Loopback);
        var capture = new WindowsCapture(item, filter);
        using var stop = new CancellationTokenSource();
        using var parent = Process.GetCurrentProcess();
        long retained = 0;
        long visible = 0;
        CaptureStatistics? stats = null;

        var cpuBefore = parent.TotalProcessorTime;
        var watch = Stopwatch.StartNew();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task capturing = Task.Run(() => capture.Run(packet =>
        {
            retained++;
            if (display(packet)) visible++;
        }, value => stats = value, stop.Token, () => started.SetResult()));

        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
            using var sender = LaunchSender(targetPort, controlPort);
            await sender.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            if (sender.ExitCode != 0) throw new InvalidOperationException($"Load generator exited {sender.ExitCode}.");
            await Task.Delay(300);
        }
        finally
        {
            stop.Cancel();
            await capturing.WaitAsync(TimeSpan.FromSeconds(4));
        }
        watch.Stop();
        parent.Refresh();
        var cpu = parent.TotalProcessorTime - cpuBefore;
        int expectedRetained = mode == "capture" ? Batches * PerBatch / 2 : Batches * PerBatch;
        int expectedVisible = mode == "none" ? Batches * PerBatch : Batches * PerBatch / 2;
        if (retained != expectedRetained || visible != expectedVisible)
            throw new InvalidOperationException($"Unexpected counts: retained {retained}/{expectedRetained}, shown {visible}/{expectedVisible}.");

        Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
            $"{mode},{Batches * PerBatch},{stats?.Received},{retained},{visible},{cpu.TotalMilliseconds:F1},{parent.PeakWorkingSet64 / 1048576.0:F1},{watch.Elapsed.TotalSeconds:F3}"));
    }

    public static async Task Send(int target, int control)
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        var a = new IPEndPoint(IPAddress.Loopback, target);
        var b = new IPEndPoint(IPAddress.Loopback, control);
        byte[] payload = new byte[PayloadSize];
        var clock = Stopwatch.StartNew();
        for (int batch = 0; batch < Batches; batch++)
        {
            long remaining = batch * IntervalMs - clock.ElapsedMilliseconds;
            if (remaining > 0) await Task.Delay(TimeSpan.FromMilliseconds(remaining));
            for (int packet = 0; packet < PerBatch; packet++)
                udp.Send(payload, payload.Length, packet % 2 == 0 ? a : b);
        }
    }

    private static Process LaunchSender(int target, int control)
    {
        string path = Environment.ProcessPath ?? throw new InvalidOperationException("Process path unavailable.");
        var info = new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = true };
        if (Path.GetFileNameWithoutExtension(path).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            info.ArgumentList.Add(typeof(CaptureBenchmark).Assembly.Location);
        info.ArgumentList.Add("load");
        info.ArgumentList.Add(target.ToString(CultureInfo.InvariantCulture));
        info.ArgumentList.Add(control.ToString(CultureInfo.InvariantCulture));
        return Process.Start(info) ?? throw new InvalidOperationException("Failed to launch load generator.");
    }
}

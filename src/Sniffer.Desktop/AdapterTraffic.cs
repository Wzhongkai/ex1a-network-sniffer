using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Media;
using Sniffer.Windows;

namespace Sniffer.Desktop;

internal sealed class AdapterTraffic(CaptureInterface networkInterface) : INotifyPropertyChanged
{
    private static readonly Pen Incoming = Stroke("#206BAB");
    private static readonly Pen Outgoing = Stroke("#B95135");
    private readonly Queue<(double Received, double Sent)> _samples = new();
    private (long Received, long Sent, long Time)? _last;
    public CaptureInterface Interface { get; } = networkInterface;
    public ImageSource? Chart { get; private set; }
    public string Rate { get; private set; } = "等待采样";
    public event PropertyChangedEventHandler? PropertyChanged;

    public void Sample(NetworkInterface? adapter)
    {
        try
        {
            if (adapter is null) { UpdateUnavailable(); return; }
            IPInterfaceStatistics stats = adapter.GetIPStatistics();
            var now = (Received: stats.BytesReceived, Sent: stats.BytesSent, Time: Stopwatch.GetTimestamp());
            if (_last is { } previous)
            {
                double seconds = Stopwatch.GetElapsedTime(previous.Time, now.Time).TotalSeconds;
                if (seconds <= 0) return;
                double received = Math.Max(0, now.Received - previous.Received) / seconds;
                double sent = Math.Max(0, now.Sent - previous.Sent) / seconds;
                _samples.Enqueue((received, sent));
                if (_samples.Count > 30) _samples.Dequeue();
                Rate = $"接收 {received / 1024:N1} KiB/s · 发送 {sent / 1024:N1} KiB/s · 最近 30 个采样";
                Draw();
                Notify();
            }
            _last = now;
        }
        catch (NetworkInformationException) { UpdateUnavailable(); }
    }

    private void UpdateUnavailable()
    {
        _last = null;
        _samples.Clear();
        if (Rate == "系统未提供此接口的流量计数") return;
        Chart = null;
        Rate = "系统未提供此接口的流量计数";
        Notify();
    }

    private void Notify()
    {
        PropertyChanged?.Invoke(this, new(nameof(Chart)));
        PropertyChanged?.Invoke(this, new(nameof(Rate)));
    }

    private void Draw()
    {
        var samples = _samples.ToArray();
        double max = Math.Max(1024, samples.Max(point => Math.Max(point.Received, point.Sent)));
        var drawing = new DrawingGroup();
        using (DrawingContext canvas = drawing.Open())
        {
            canvas.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, 54, 18));
            DrawSeries(canvas, samples.Select(point => point.Received), max, Incoming);
            DrawSeries(canvas, samples.Select(point => point.Sent), max, Outgoing);
        }
        var image = new DrawingImage(drawing);
        image.Freeze();
        Chart = image;
    }

    private static void DrawSeries(DrawingContext canvas, IEnumerable<double> values, double max, Pen pen)
    {
        double[] samples = values.ToArray();
        Point At(int index) => new(53 - (samples.Length - 1 - index) * 52d / 29, 17 - 15 * samples[index] / max);
        if (samples.Length == 1) canvas.DrawEllipse(pen.Brush, null, At(0), 1, 1);
        for (int i = 1; i < samples.Length; i++)
            canvas.DrawLine(pen, At(i - 1), At(i));
    }

    private static Pen Stroke(string color)
    {
        var pen = new Pen(new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)), 1);
        pen.Freeze();
        return pen;
    }
}

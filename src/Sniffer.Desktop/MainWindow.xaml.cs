using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text;
using System.Threading.Channels;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Sniffer.Core;
using Sniffer.Windows;

namespace Sniffer.Desktop;

public partial class MainWindow : Window
{
    private const int HistoryCount = 6000;
    private const int HistoryBytes = 64 * 1024 * 1024;
    private const int PageSize = 512;
    private readonly Queue<Packet> _history = new();
    private readonly ObservableCollection<Packet> _visible = [];
    private readonly DispatcherTimer _refresh = new() { Interval = TimeSpan.FromMilliseconds(85) };
    private readonly DispatcherTimer _traffic = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Dictionary<IPAddress, string> _names = [];
    private HashSet<IPAddress> _localAddresses = [];
    private readonly Dictionary<AdapterTraffic, NetworkInterface?> _adapters = [];
    private string _colorText = DisplaySettingsWindow.DefaultRules;
    private IReadOnlyList<PacketColorRule> _colorRules = DisplaySettingsWindow.Parse(DisplaySettingsWindow.DefaultRules);
    private bool _showNames = true;
    private bool _showColors = true;
    private readonly bool _hasAdministratorAccess = IsAdministrator();
    private LiveAnalysis _analysis = new();
    private CaptureJob? _job;
    private CaptureJob? _lastJob;
    private Func<Packet, bool> _filter = DisplayFilter.Compile("");
    private Func<Packet, bool> _protocolFilter = DisplayFilter.Compile("");
    private int _bytes;
    private long _evicted;
    private int _page;
    private (int Offset, int Length) _highlight;
    private bool _saving;
    private bool _enumerating;
    private bool _closing;
    private bool _allowClose;

    public MainWindow()
    {
        InitializeComponent();
        Rect area = SystemParameters.WorkArea;
        double availableWidth = Math.Max(1, area.Width - 32);
        double availableHeight = Math.Max(1, area.Height - 32);
        MinWidth = Math.Min(MinWidth, availableWidth);
        MinHeight = Math.Min(MinHeight, availableHeight);
        Width = Math.Min(Width, availableWidth);
        Height = Math.Min(Height, availableHeight);
        PacketGrid.ItemsSource = _visible;
        ProtocolFilterBox.SelectedIndex = 0;
        _refresh.Tick += (_, _) => Drain();
        _refresh.Start();
        _traffic.Tick += (_, _) => SampleAdapters();
        _traffic.Start();
        UpdateControls();
        UpdateCounters();
        DrawHex();
    }

    private async void OnLoaded(object sender, RoutedEventArgs args)
    {
        string[] startup = Environment.GetCommandLineArgs();
        int capture = Array.IndexOf(startup, "--capture-interface");
        string? requested = capture >= 0 && capture + 2 < startup.Length ? startup[capture + 1] : null;
        await RefreshInterfaces(requested);
        if (!_hasAdministratorAccess || requested is null) return;
        if (SelectedInterface?.Name != requested)
        {
            StatusText.Text = "所选接口当前不可用于抓包，请重新选择。";
            return;
        }
        CaptureFilterBox.Text = startup[capture + 2];
        await StartCapture();
    }
    private async void OnRefresh(object sender, RoutedEventArgs args) => await RefreshInterfaces();

    private CaptureInterface? SelectedInterface => (InterfacesBox.SelectedItem as AdapterTraffic)?.Interface;

    private void SampleAdapters()
    {
        foreach (var row in _adapters) row.Key.Sample(row.Value);
    }

    private async Task RefreshInterfaces(string? requested = null)
    {
        if (_enumerating || _job is not null) return;
        _enumerating = true;
        UpdateControls();
        string? selected = SelectedInterface?.Id;
        try
        {
            var interfaces = await Task.Run(() => _hasAdministratorAccess
                ? WindowsCapture.Interfaces()
                : WindowsCapture.PreviewInterfaces());
            var nics = NetworkInterface.GetAllNetworkInterfaces();
            _localAddresses = nics.SelectMany(nic => nic.GetIPProperties().UnicastAddresses)
                .Select(address => Connections.Normalize(address.Address)).ToHashSet();
            var loopback = nics.FirstOrDefault(nic => nic.NetworkInterfaceType == NetworkInterfaceType.Loopback);
            _adapters.Clear();
            var rows = interfaces.Select(item => new AdapterTraffic(item)).ToArray();
            foreach (AdapterTraffic row in rows)
                _adapters.Add(row, row.Interface.Loopback ? loopback :
                    nics.FirstOrDefault(nic => nic.Id.Equals(row.Interface.AdapterId, StringComparison.OrdinalIgnoreCase)));
            InterfacesBox.ItemsSource = rows;
            InterfacesBox.SelectedItem = rows.FirstOrDefault(row => row.Interface.Name == requested)
                ?? rows.FirstOrDefault(row => row.Interface.Id == selected) ?? rows.FirstOrDefault();
            SampleAdapters();
            StatusText.Text = interfaces.Count == 0 ? "未找到 Windows 捕获接口。" :
                !_hasAdministratorAccess ? $"已找到 {interfaces.Count} 个接口。实时抓包需要管理员权限。" :
                $"已找到 {interfaces.Count} 个接口";
        }
        catch (Exception error)
        {
            StatusText.Text = error.Message;
            InterfacesBox.ItemsSource = null;
        }
        finally
        {
            _enumerating = false;
            UpdateControls();
        }
    }

    private async void OnStart(object sender, RoutedEventArgs args) => await StartCapture();

    private async Task StartCapture()
    {
        if (SelectedInterface is not { } item || _job is not null) return;
        string filter = CaptureFilterBox.Text.Trim();
        WindowsCapture capture;
        try
        {
            capture = new WindowsCapture(item, filter);
            if (!_hasAdministratorAccess)
            {
                StartElevated(item, filter);
                return;
            }
        }
        catch (Exception error)
        {
            StatusText.Text = error.Message;
            return;
        }

        await Run($"实时捕获 · {item.Name}", true, job =>
        {
            using var ownership = _analysis.TrackSockets();
            capture.Run(job.AcceptLive, job.SetStatistics, job.Cancellation.Token);
        });
    }

    private void StartElevated(CaptureInterface item, string filter)
    {
        string executable = Environment.ProcessPath ?? throw new IOException("找不到当前程序。");
        var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas" };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Path.GetFullPath(Environment.GetCommandLineArgs()[0]));
        start.ArgumentList.Add("--capture-interface");
        start.ArgumentList.Add(item.Name);
        start.ArgumentList.Add(filter);
        try
        {
            using Process? process = Process.Start(start);
            StatusText.Text = "抓包将在管理员窗口中运行。";
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            StatusText.Text = "已取消管理员启动。";
        }
    }

    private static bool IsAdministrator()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void OnStop(object sender, RoutedEventArgs args)
    {
        if (_job is null) return;
        StopButton.IsEnabled = false;
        StatusText.Text = "正在停止…";
        _job.Cancellation.Cancel();
    }

    private async void OnDemo(object sender, RoutedEventArgs args) => await Run("演示流量 · 合成样本", false,
        job => job.Read(DemoTrace.Read()));

    private async void OnOpen(object sender, RoutedEventArgs args)
    {
        if (_job is not null) return;
        var picker = new OpenFileDialog { Filter = "抓包文件 (*.pcap;*.pcapng)|*.pcap;*.pcapng|经典 PCAP (*.pcap)|*.pcap|PCAPNG (*.pcapng)|*.pcapng|所有文件 (*.*)|*.*" };
        if (picker.ShowDialog(this) != true) return;
        await Run($"离线 · {Path.GetFileName(picker.FileName)}", false, job =>
        {
            using var stream = File.OpenRead(picker.FileName);
            job.Read(CaptureFile.Read(stream));
        });
    }

    private async void OnSave(object sender, RoutedEventArgs args)
    {
        if (_visible.Count == 0 || _saving) return;
        var picker = new SaveFileDialog { Filter = "PCAPNG (*.pcapng)|*.pcapng|经典 PCAP (*.pcap)|*.pcap", DefaultExt = ".pcapng",
            FileName = "sniffer", Title = "保存当前可见的报文" };
        if (picker.ShowDialog(this) != true || _visible.Count == 0) return;
        RawPacket[] snapshot = _visible.Select(packet => packet.Raw).ToArray();
        _saving = true;
        UpdateControls();
        try
        {
            await Task.Run(() =>
            {
                bool classic = Path.GetExtension(picker.FileName).Equals(".pcap", StringComparison.OrdinalIgnoreCase);
                if (classic && snapshot.Any(packet => packet.Link != snapshot[0].Link))
                    throw new InvalidDataException("这些报文使用不同的链路类型，请选择 PCAPNG。");
                string target = picker.FileName;
                string temporary = Path.Combine(Path.GetDirectoryName(target)!, $".sniffer-{Guid.NewGuid():N}.tmp");
                try
                {
                    using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write))
                    {
                        if (classic)
                        {
                            var writer = new PcapWriter(stream, snapshot[0].Link);
                            foreach (RawPacket raw in snapshot) writer.Write(raw);
                        }
                        else
                            PcapNg.Write(stream, snapshot);
                    }
                    File.Move(temporary, target, overwrite: true);
                }
                finally { File.Delete(temporary); }
            });
            StatusText.Text = $"已保存当前可见的 {snapshot.Length} 个报文 · {Path.GetFileName(picker.FileName)}";
        }
        catch (Exception error) { StatusText.Text = $"保存失败：{error.Message}"; }
        finally
        {
            _saving = false;
            UpdateControls();
        }
    }

    private async Task Run(string title, bool live, Action<CaptureJob> action)
    {
        if (_job is not null) return;
        Reset();
        using var job = new CaptureJob(_analysis, live);
        _lastJob = _job = job;
        StatusText.Text = title;
        UpdateControls();
        UpdateCounters();
        try
        {
            await Task.Run(() => action(job));
            StatusText.Text = job.Cancellation.IsCancellationRequested ? $"已停止 · {title}" : $"已完成 · {title}";
        }
        catch (OperationCanceledException) when (job.Cancellation.IsCancellationRequested)
        {
            StatusText.Text = $"已停止 · {title}";
        }
        catch (Exception error)
        {
            StatusText.Text = $"{title} · {error.Message}";
        }
        finally
        {
            Drain(int.MaxValue);
            if (live && _analysis.SocketEventsUnavailable is not null)
                StatusText.Text += " · 短连接 PID 事件不可用，已使用 TCP 表查询";
            _job = null;
            UpdateControls();
            UpdateCounters();
            if (_closing)
            {
                _allowClose = true;
                Close();
            }
        }
    }

    private void Reset()
    {
        _analysis = new LiveAnalysis();
        _history.Clear();
        _names.Clear();
        _visible.Clear();
        _bytes = 0;
        _evicted = 0;
    }

    private void Drain(int limit = 512)
    {
        if (_job is not { } job) return;
        bool learnedName = false;
        for (int i = 0; i < limit && job.Packets.Reader.TryRead(out Packet? packet); i++)
        {
            foreach (DnsAddress answer in packet.DnsAddresses)
            {
                IPAddress address = Connections.Normalize(answer.Address);
                if (_names.GetValueOrDefault(address) == answer.Name) continue;
                if (_names.Count == 4096 && !_names.ContainsKey(address)) _names.Remove(_names.First().Key);
                _names[address] = answer.Name;
                learnedName = true;
            }
            Decorate(packet);
            _history.Enqueue(packet);
            _bytes += packet.Raw.Bytes.Length;
            if (MatchesFilter(packet)) _visible.Add(packet);
            while (_history.Count > HistoryCount || _bytes > HistoryBytes)
            {
                Packet removed = _history.Dequeue();
                _bytes -= removed.Raw.Bytes.Length;
                if (_visible.Count > 0 && ReferenceEquals(removed, _visible[0]))
                    _visible.RemoveAt(0);
                _evicted++;
            }
        }
        // A PID can be learned after the packet was already shown, so the earlier rows must be re-tested.
        if (_analysis.Flows.ConsumeOwnersChanged() | learnedName) RefreshVisible();
        UpdateControls();
        UpdateCounters();
    }

    private void UpdateControls()
    {
        bool active = _job is not null;
        RefreshButton.IsEnabled = !active && !_enumerating;
        InterfacesBox.IsEnabled = !active && !_enumerating;
        StartButton.IsEnabled = !active && !_enumerating && InterfacesBox.Items.Count > 0;
        StartButton.Content = _hasAdministratorAccess ? "开始捕获" : "以管理员身份捕获";
        CaptureFilterBox.IsEnabled = !active;
        StopButton.IsEnabled = active && _job?.Cancellation.IsCancellationRequested == false;
        OpenButton.IsEnabled = DemoButton.IsEnabled = !active;
        SaveButton.IsEnabled = !_saving && _visible.Count > 0;
        FollowButton.IsEnabled = (PacketGrid.SelectedItem as Packet)?.FlowId is not null;
    }

    private void UpdateCounters()
    {
        CaptureJob? job = _lastJob;
        string driver = job is { Live: true } ? $"  ·  采集丢弃 {job.CaptureDropped?.ToString("N0") ?? "—"}" : "";
        CounterText.Text = $"显示 {_visible.Count:N0}/{_history.Count:N0}  ·  接收 {job?.Accepted ?? 0:N0}" +
            $"  ·  队列丢弃 {job?.Dropped ?? 0:N0}  ·  淘汰 {_evicted:N0}{driver}";
        EmptyTitle.Text = _history.Count > 0 ? "当前过滤条件没有匹配报文" :
            _job is not null ? "等待报文…" : "选择接口后开始捕获";
        EmptyState.Visibility = _visible.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnApplyFilter(object sender, RoutedEventArgs args) => ApplyFilter();
    private void OnFilterKey(object sender, KeyEventArgs args)
    {
        if (args.Key != Key.Enter) return;
        args.Handled = true;
        ApplyFilter();
    }

    private void OnClearFilter(object sender, RoutedEventArgs args)
    {
        DisplayFilterBox.Clear();
        ProtocolFilterBox.SelectedIndex = 0;
        ApplyFilter();
    }

    private void OnProtocolChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs args)
    {
        if (ProtocolFilterBox.SelectedItem is not System.Windows.Controls.ComboBoxItem item) return;
        _protocolFilter = DisplayFilter.Compile(item.Tag as string ?? "");
        RefreshVisible();
    }

    private void ApplyFilter()
    {
        try
        {
            _filter = DisplayFilter.Compile(DisplayFilterBox.Text);
            DisplayFilterBox.BorderBrush = (Brush)FindResource("Line");
        }
        catch (FormatException error)
        {
            DisplayFilterBox.BorderBrush = Brushes.Firebrick;
            StatusText.Text = error.Message;
            return;
        }
        StatusText.Text = string.IsNullOrWhiteSpace(DisplayFilterBox.Text) ? "已清除显示表达式" : $"已应用 · {DisplayFilterBox.Text}";
        RefreshVisible();
    }

    private bool MatchesFilter(Packet packet) => _protocolFilter(packet) && _filter(packet);

    private string? Hostname(IPAddress? address) => _showNames && address is not null
        ? _names.GetValueOrDefault(Connections.Normalize(address)) : null;

    private void Decorate(Packet packet)
    {
        packet.SourceName = Hostname(packet.Source);
        packet.DestinationName = Hostname(packet.Destination);
        packet.Color = _showColors ? _colorRules.FirstOrDefault(rule => rule.Matches(packet))?.Color : null;
    }

    private void OnDisplaySettings(object sender, RoutedEventArgs args)
    {
        var settings = new DisplaySettingsWindow(_showNames, _showColors, _colorText) { Owner = this };
        if (settings.ShowDialog() != true) return;
        _showNames = settings.ShowNames;
        _showColors = settings.ShowColors;
        _colorText = settings.RulesText;
        _colorRules = settings.Rules;
        RefreshVisible();
    }

    private void OnConnections(object sender, RoutedEventArgs args)
    {
        var dialog = new ConnectionsWindow(() => (Connections.Summarize(_history, _localAddresses),
            _showNames ? _names : new Dictionary<IPAddress, string>(), _history.Count)) { Owner = this };
        dialog.ShowDialog();
    }

    private void RefreshVisible()
    {
        Packet? selected = PacketGrid.SelectedItem as Packet;
        var matched = _history.Where(MatchesFilter).ToArray();
        foreach (Packet packet in matched) Decorate(packet);
        if (_visible.SequenceEqual(matched))
            PacketGrid.Items.Refresh();
        else
        {
            _visible.Clear();
            foreach (Packet packet in matched) _visible.Add(packet);
        }
        if (selected is not null && MatchesFilter(selected)) PacketGrid.SelectedItem = selected;
        UpdateControls();
        UpdateCounters();
    }

    private void OnPacketSelected(object sender, System.Windows.Controls.SelectionChangedEventArgs args)
    {
        var packet = PacketGrid.SelectedItem as Packet;
        if (packet is null) DetailsTree.ItemsSource = null;
        else
        {
            var frame = new PacketLayer($"帧 {packet.Number} · 捕获 {packet.Raw.Bytes.Length} / 原始 {packet.Raw.WireLength} 字节",
                0, 0, [new PacketField("时间", packet.Raw.Timestamp.ToString("O"), 0, 0),
                new PacketField("链路", packet.Raw.Link.ToString(), 0, 0)]);
            DetailsTree.ItemsSource = new[] { frame }.Concat(packet.Layers).ToArray();
        }
        FollowButton.IsEnabled = packet?.FlowId is not null;
        _page = 0;
        _highlight = (0, 0);
        DrawHex();
    }

    private void OnFieldSelected(object sender, RoutedPropertyChangedEventArgs<object> args)
    {
        _highlight = args.NewValue switch
        {
            PacketField field => (field.Offset, field.Length),
            PacketLayer layer => (layer.Offset, layer.Length),
            _ => (0, 0)
        };
        if (_highlight.Length > 0) _page = _highlight.Offset / PageSize;
        DrawHex();
    }

    private void OnPreviousPage(object sender, RoutedEventArgs args)
    {
        if (_page > 0) _page--;
        DrawHex();
    }

    private void OnNextPage(object sender, RoutedEventArgs args)
    {
        if (PacketGrid.SelectedItem is Packet packet && (_page + 1) * PageSize < packet.Raw.Bytes.Length) _page++;
        DrawHex();
    }

    private void DrawHex()
    {
        if (HexBox is null) return;
        byte[] bytes = (PacketGrid.SelectedItem as Packet)?.Raw.Bytes ?? [];
        int pages = (bytes.Length + PageSize - 1) / PageSize;
        _page = Math.Clamp(_page, 0, Math.Max(0, pages - 1));
        int start = _page * PageSize;
        int end = Math.Min(start + PageSize, bytes.Length);
        HexPage.Text = pages == 0 ? "—" : $"{_page + 1} / {pages}";
        PrevPage.IsEnabled = _page > 0;
        NextPage.IsEnabled = _page + 1 < pages;

        var paragraph = new Paragraph { Margin = new Thickness(0), LineHeight = 17 };
        for (int offset = start; offset < end; offset += 16)
        {
            paragraph.Inlines.Add(new Run($"{offset:X6}  ") { Foreground = (Brush)FindResource("Muted") });
            var ascii = new StringBuilder(16);
            for (int i = 0; i < 16; i++)
            {
                int index = offset + i;
                if (index >= end) paragraph.Inlines.Add(new Run("   "));
                else
                {
                    byte value = bytes[index];
                    var hex = new Run($"{value:X2} ");
                    if (index >= _highlight.Offset && index - _highlight.Offset < _highlight.Length)
                        hex.Background = Brushes.LightSkyBlue;
                    paragraph.Inlines.Add(hex);
                    ascii.Append(value is >= 32 and < 127 ? (char)value : '.');
                }
                if (i == 7) paragraph.Inlines.Add(new Run(" "));
            }
            paragraph.Inlines.Add(new Run($"  |{ascii}|") { Foreground = (Brush)FindResource("Muted") });
            if (offset + 16 < end) paragraph.Inlines.Add(new LineBreak());
        }
        if (end == start) paragraph.Inlines.Add(new Run("选择一个报文查看原始字节。"));
        HexBox.Document = new FlowDocument(paragraph) { PagePadding = new Thickness(0), MinPageWidth = 555 };
    }

    private void OnFollow(object sender, RoutedEventArgs args) => ShowSelectedFlow();
    private void OnPacketDoubleClick(object sender, MouseButtonEventArgs args)
    {
        if (args.OriginalSource is DependencyObject source && System.Windows.Controls.ItemsControl.ContainerFromElement(PacketGrid, source) is not null)
            ShowSelectedFlow();
    }

    private void ShowSelectedFlow()
    {
        if ((PacketGrid.SelectedItem as Packet)?.FlowId is long id)
        {
            if (_analysis.Flows.Find(id) is null) StatusText.Text = "此会话的追踪记录已淘汰。";
            else ShowFlows(id);
        }
    }

    private void OnFlows(object sender, RoutedEventArgs args) => ShowFlows(null);

    private void ShowFlows(long? id)
    {
        var dialog = new FlowsWindow(_analysis.Flows, id) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.SelectedFlowId is long flowId)
        {
            ProtocolFilterBox.SelectedIndex = 0;
            DisplayFilterBox.Text = $"stream == {flowId}";
            ApplyFilter();
        }
    }

    private void OnClosing(object? sender, CancelEventArgs args)
    {
        if (_allowClose || _job is null)
        {
            _refresh.Stop();
            _traffic.Stop();
            return;
        }
        args.Cancel = true;
        _closing = true;
        _job.Cancellation.Cancel();
    }

    private sealed class CaptureJob(LiveAnalysis analysis, bool live) : IDisposable
    {
        private long _accepted;
        private long _dropped;
        private long _captureDropped = -1;

        public bool Live { get; } = live;
        public CancellationTokenSource Cancellation { get; } = new();
        public Channel<Packet> Packets { get; } = Channel.CreateBounded<Packet>(
            new BoundedChannelOptions(512) { SingleReader = true, SingleWriter = true });
        public long Accepted => Interlocked.Read(ref _accepted);
        public long Dropped => Interlocked.Read(ref _dropped);
        public long? CaptureDropped
        {
            get
            {
                long value = Interlocked.Read(ref _captureDropped);
                return value >= 0 ? value : null;
            }
        }

        public void SetStatistics(CaptureStatistics stats) => Interlocked.Exchange(ref _captureDropped, stats.Dropped ?? -1);

        public void AcceptLive(Packet packet)
        {
            Interlocked.Increment(ref _accepted);
            analysis.Observe(packet, true);
            if (!Packets.Writer.TryWrite(packet)) Interlocked.Increment(ref _dropped);
        }

        public void Read(IEnumerable<RawPacket> packets)
        {
            foreach (RawPacket packet in packets)
            {
                Cancellation.Token.ThrowIfCancellationRequested();
                Interlocked.Increment(ref _accepted);
                Packets.Writer.WriteAsync(analysis.Decode(packet, false), Cancellation.Token)
                    .AsTask().GetAwaiter().GetResult();
            }
        }

        public void Dispose() => Cancellation.Dispose();
    }
}

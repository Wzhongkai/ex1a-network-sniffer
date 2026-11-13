using System.Windows;
using System.Windows.Controls;
using System.IO;
using Microsoft.Win32;
using Sniffer.Core;

namespace Sniffer.Desktop;

public partial class FlowsWindow : Window
{
    private readonly FlowTracker _tracker;
    private bool _updating;
    private long? _decryptedFlow;

    public FlowsWindow(FlowTracker tracker, long? selected)
    {
        _tracker = tracker;
        InitializeComponent();
        Refresh(selected);
    }

    public long? SelectedFlowId => (FlowGrid.SelectedItem as FlowSnapshot)?.Id;

    private void OnRefresh(object sender, RoutedEventArgs args) => Refresh(SelectedFlowId);

    private void Refresh(long? selected)
    {
        _updating = true;
        int? pid = (Processes.SelectedItem as ProcessChoice)?.Pid;
        var known = _tracker.List()
            .SelectMany(flow => flow.Owners).GroupBy(owner => owner.Pid).Select(group => group.First())
            .OrderBy(owner => owner.Name).ThenBy(owner => owner.Pid)
            .Select(owner => new ProcessChoice(owner.Pid, owner.Label)).ToList();
        known.Insert(0, new ProcessChoice(null, "所有会话"));
        Processes.ItemsSource = known;
        Processes.SelectedItem = known.FirstOrDefault(choice => choice.Pid == pid) ?? known[0];
        _updating = false;
        ShowList(selected);
    }

    private void OnProcessChanged(object sender, SelectionChangedEventArgs args)
    {
        if (!_updating) ShowList(SelectedFlowId);
    }

    private void ShowList(long? selected)
    {
        var flows = _tracker.List((Processes.SelectedItem as ProcessChoice)?.Pid);
        FlowGrid.ItemsSource = flows;
        FlowGrid.SelectedItem = flows.FirstOrDefault(flow => flow.Id == selected) ?? flows.FirstOrDefault();
        CountLabel.Text = $"{flows.Count:N0} 条会话";
        if (FlowGrid.SelectedItem is { } row) FlowGrid.ScrollIntoView(row);
        ShowDetails();
    }

    private void OnFlowChanged(object sender, SelectionChangedEventArgs args) => ShowDetails();

    private void ShowDetails()
    {
        if (!IsInitialized) return;
        FlowSnapshot? flow = SelectedFlowId is long id ? _tracker.Find(id) : null;
        FlowLabel.Text = flow is null ? "选择会话查看时间线和重组数据" : $"会话 {flow.Id} · {flow.Endpoints}";
        Timeline.ItemsSource = flow?.Timeline;
        Forward.Text = flow?.ForwardText ?? "";
        Reverse.Text = flow?.ReverseText ?? "";
        ForwardStatus.Text = Direction("A → B", flow?.ForwardStatus);
        ReverseStatus.Text = Direction("B → A", flow?.ReverseStatus);
        FilterPacketsButton.IsEnabled = flow is not null;
        if (SelectedFlowId != _decryptedFlow || _decryptedFlow is null) ShowTls();
    }

    private void ShowTls(TextReader? keys = null)
    {
        TlsStreamData? data = SelectedFlowId is long id ? _tracker.ReadTlsStream(id) : null;
        TlsInspection? report = data is null ? null : TlsInspector.Inspect(data, keys);
        TlsStatus.Text = report?.Status ?? "选择一个 TLS 会话后查看记录和握手。";
        TlsRecords.ItemsSource = report?.Records;
        TlsForward.Text = report?.ForwardText ?? "";
        TlsReverse.Text = report?.ReverseText ?? "";
        _decryptedFlow = keys is null ? null : SelectedFlowId;
        LoadKeys.IsEnabled = report?.Records.Count > 0;
        ClearKeys.IsEnabled = _decryptedFlow.HasValue;
    }

    private void OnClearKeys(object sender, RoutedEventArgs args) => ShowTls();

    private void OnLoadKeys(object sender, RoutedEventArgs args)
    {
        var picker = new OpenFileDialog
        {
            Title = "选择此会话对应的 SSLKEYLOGFILE",
            Filter = "密钥日志 (*.log;*.txt;*.keys)|*.log;*.txt;*.keys|所有文件 (*.*)|*.*"
        };
        if (picker.ShowDialog(this) != true) return;
        try
        {
            using var file = File.Open(picker.FileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (file.Length > 16 * 1024 * 1024) throw new InvalidDataException("密钥日志上限为 16 MiB。");
            using var reader = new StreamReader(file);
            ShowTls(reader);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            TlsStatus.Text = $"无法读取密钥日志 · {error.Message}";
        }
    }

    private static string Direction(string name, string? status) => string.IsNullOrEmpty(status) ? name : $"{name} · {status}";

    private void OnShowPackets(object sender, RoutedEventArgs args) => DialogResult = SelectedFlowId is not null;

    private sealed record ProcessChoice(int? Pid, string Label);
}

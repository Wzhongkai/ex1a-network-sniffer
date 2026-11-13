using System.Net;
using System.Windows;
using System.Windows.Threading;
using Sniffer.Core;

namespace Sniffer.Desktop;

public partial class ConnectionsWindow : Window
{
    private static readonly Lazy<Task<CountryLookup>> Countries = new(() => Task.Run(() => new CountryLookup()));
    private readonly Func<(IReadOnlyList<ConnectionRow> Rows, IReadOnlyDictionary<IPAddress, string> Names, int Packets)> _read;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };
    private bool _refreshing;
    private bool _closed;

    internal ConnectionsWindow(Func<(IReadOnlyList<ConnectionRow> Rows, IReadOnlyDictionary<IPAddress, string> Names, int Packets)> read)
    {
        _read = read;
        InitializeComponent();
        _timer.Tick += (_, _) => UpdateRows();
        _timer.Start();
    }

    private void OnRefresh(object sender, RoutedEventArgs args) => UpdateRows();

    private async void UpdateRows()
    {
        if (_refreshing) return;
        _refreshing = true;
        try
        {
            var snapshot = _read();
            CountryLookup? countries = null;
            string? countryError = null;
            if (snapshot.Rows.Count > 0)
            {
                Task<CountryLookup> countryTask = Countries.Value;
                if (!countryTask.IsCompleted) Status.Text = "正在载入离线国家和地区数据库…";
                try { countries = await countryTask; }
                catch (Exception error) when (error is System.IO.IOException) { countryError = " · 地区数据无法载入"; }
            }
            if (_closed) return;
            var rows = snapshot.Rows.Select(row => new DisplayRow(row,
                Address(row.Local, snapshot.Names), Address(row.Remote, snapshot.Names),
                row.Direction == "本机双端" ? "本地" : countries?.Find(row.Remote) ?? "—")).ToArray();
            if (GridRows.ItemsSource is not DisplayRow[] previous || !previous.SequenceEqual(rows))
            {
                var selected = (GridRows.SelectedItem as DisplayRow)?.Row;
                GridRows.ItemsSource = rows;
                if (selected is not null)
                    GridRows.SelectedItem = rows.FirstOrDefault(item => item.Row.Local.Equals(selected.Local) &&
                        item.Row.Remote.Equals(selected.Remote) && item.Row.Direction == selected.Direction);
            }
            Status.Text = $"最近保留的 {snapshot.Packets:N0} 个报文 · {rows.Length:N0} 个地址对{countryError}";
        }
        catch (Exception error) { Status.Text = error.Message; }
        finally { _refreshing = false; }
    }

    private static string Address(IPAddress ip, IReadOnlyDictionary<IPAddress, string> names) =>
        names.TryGetValue(ip, out string? name) ? $"{ip} · {name}" : ip.ToString();

    private void OnClosed(object? sender, EventArgs args)
    {
        _closed = true;
        _timer.Stop();
    }

    private sealed record DisplayRow(ConnectionRow Row, string LocalText, string RemoteText, string Country);
}

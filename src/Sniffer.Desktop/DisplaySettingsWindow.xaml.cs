using System.Windows;
using Sniffer.Core;

namespace Sniffer.Desktop;

public partial class DisplaySettingsWindow : Window
{
    internal const string DefaultRules = "http = #E5F5E9\ndns = #FFF4D7\ntls = #EEE8FC\nicmp || icmpv6 = #FDE9E7\narp = #FFEBD8\ntcp = #E9F3FE\nudp = #E4F4F4";

    public DisplaySettingsWindow(bool names, bool colors, string text)
    {
        InitializeComponent();
        NamesBox.IsChecked = names;
        ColorsBox.IsChecked = colors;
        RulesBox.Text = text;
    }

    public bool ShowNames => NamesBox.IsChecked == true;
    public bool ShowColors => ColorsBox.IsChecked == true;
    public string RulesText => RulesBox.Text;
    internal IReadOnlyList<PacketColorRule> Rules { get; private set; } = [];

    internal static IReadOnlyList<PacketColorRule> Parse(string text)
    {
        var rules = new List<PacketColorRule>();
        string[] lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (line.Length == 0) continue;
            int separator = line.LastIndexOf('=');
            string color = separator < 0 ? "" : line[(separator + 1)..].Trim();
            if (separator <= 0 || color.Length != 7 || color[0] != '#' || !color[1..].All(Uri.IsHexDigit))
                throw new FormatException($"第 {i + 1} 行需要「表达式 = #RRGGBB」。");
            try { rules.Add(new PacketColorRule(DisplayFilter.Compile(line[..separator].Trim()), color)); }
            catch (FormatException error) { throw new FormatException($"第 {i + 1} 行 · {error.Message}", error); }
            if (rules.Count > 32) throw new FormatException("最多可使用 32 条着色规则。");
        }
        return rules;
    }

    private void OnDefaults(object sender, RoutedEventArgs args) => RulesBox.Text = DefaultRules;

    private void OnApply(object sender, RoutedEventArgs args)
    {
        try { Rules = Parse(RulesText); }
        catch (FormatException error) { ErrorText.Text = error.Message; return; }
        DialogResult = true;
    }
}

internal sealed record PacketColorRule(Func<Packet, bool> Matches, string Color);

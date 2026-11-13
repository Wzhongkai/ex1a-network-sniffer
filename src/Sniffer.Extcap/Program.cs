using System.Globalization;
using System.IO.Pipes;
using System.Text;
using Sniffer.Core;
using Sniffer.Extcap;
using Sniffer.Windows;

try
{
    Console.OutputEncoding = new UTF8Encoding(false);
    var options = ReadOptions(args);
    if (options.ContainsKey("--help"))
    {
        Console.WriteLine("Sniffer.Extcap: --extcap-interfaces | --extcap-interface <id> --extcap-dlts | --extcap-config");
        Console.WriteLine("Capture: --extcap-interface <id> --capture --pid <number> --fifo <pipe> [--extcap-capture-filter <expression>]");
        return 0;
    }
    if (options.ContainsKey("--extcap-interfaces") || options.Count == 0)
    {
        Console.WriteLine("extcap {version=1.0.0}{help=https://www.wireshark.org/docs/man-pages/extcap.html}");
        foreach (CaptureInterface nic in WindowsCapture.Interfaces())
            Console.WriteLine($"interface {{value={EncodeId(nic.Id)}}}{{display=TCP by PID — {SafeLabel(nic.Name)}}}");
        return 0;
    }

    string interfaceId = Required(options, "--extcap-interface");
    CaptureInterface item = WindowsCapture.Interfaces().FirstOrDefault(nic => EncodeId(nic.Id) == interfaceId)
        ?? throw new ArgumentException("The selected Windows interface is unavailable.");
    if (options.ContainsKey("--extcap-config"))
    {
        Console.WriteLine("arg {number=0}{call=--pid}{display=Local process ID}{type=integer}{range=1,2147483647}{required=true}");
        return 0;
    }
    if (options.ContainsKey("--extcap-dlts"))
    {
        Console.WriteLine(item.Link == LinkType.RawIp
            ? "dlt {number=101}{name=RAW}{display=Raw IP}"
            : "dlt {number=1}{name=EN10MB}{display=Ethernet}");
        return 0;
    }

    string filter = options.GetValueOrDefault("--extcap-capture-filter") ?? "";
    if (!options.ContainsKey("--capture"))
    {
        if (!options.ContainsKey("--extcap-capture-filter")) throw new ArgumentException("Missing extcap operation.");
        DisplayFilter.CompileCapture(filter);
        return 0;
    }
    if (!int.TryParse(Required(options, "--pid"), NumberStyles.None, CultureInfo.InvariantCulture, out int pid) || pid <= 0)
        throw new ArgumentException("A positive local PID is required.");

    string destination = Required(options, "--fifo");
    var capture = new WindowsCapture(item, filter);
    using Stream output = OpenOutput(destination);
    using var cancellation = new CancellationTokenSource();
    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        cancellation.Cancel();
    };
    var writer = new PcapWriter(output, capture.Link);
    output.Flush();
    var analysis = new LiveAnalysis();
    using var ownership = analysis.TrackSockets();
    var processPackets = new ProcessPackets(pid, writer.Write);
    bool pipeClosed = false;
    object outputGate = new();
    void WriteCapture(Action action)
    {
        lock (outputGate)
        {
            if (pipeClosed || cancellation.IsCancellationRequested) return;
            try { action(); }
            catch (IOException error) when (output is NamedPipeClientStream &&
                (error.HResult & 0xffff) is 109 or 232 or 233)
            {
                pipeClosed = true;
                cancellation.Cancel();
            }
            catch (IOException error)
            {
                pipeClosed = true;
                Console.Error.WriteLine(error.Message);
                cancellation.Cancel();
            }
        }
    }
    using var delayedOwners = new Timer(_ =>
    {
        WriteCapture(() =>
        {
            if (analysis.Flows.ConsumeOwnersChanged() && processPackets.FlushNewOwners()) output.Flush();
        });
    }, null, 100, 100);
    try
    {
        capture.Run(packet =>
        {
            analysis.Observe(packet, true);
            WriteCapture(() =>
            {
                processPackets.Accept(packet);
                output.Flush();
            });
        }, _ => { }, cancellation.Token);
    }
    finally { await delayedOwners.DisposeAsync(); }
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error.Message);
    return 1;
}

static Dictionary<string, string> ReadOptions(string[] arguments)
{
    var result = new Dictionary<string, string>(StringComparer.Ordinal);
    for (int i = 0; i < arguments.Length; i++)
    {
        string arg = arguments[i];
        if (!arg.StartsWith("--")) throw new ArgumentException($"Unexpected argument: {arg}");
        int equal = arg.IndexOf('=');
        if (equal >= 0)
            result[arg[..equal]] = arg[(equal + 1)..];
        else if (i + 1 < arguments.Length && !arguments[i + 1].StartsWith("--"))
            result[arg] = arguments[++i];
        else
            result[arg] = "";
    }
    return result;
}

static string Required(Dictionary<string, string> options, string key) =>
    options.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value)
        ? value : throw new ArgumentException($"Missing {key}.");

static string EncodeId(string value) => "sniffer-" + Convert.ToHexString(Encoding.UTF8.GetBytes(value)).ToLowerInvariant();

static string SafeLabel(string value) => value.Replace('{', '(').Replace('}', ')').Replace('\r', ' ').Replace('\n', ' ');

static Stream OpenOutput(string path)
{
    const string prefix = @"\\.\pipe\";
    if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        return new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
    var pipe = new NamedPipeClientStream(".", path[prefix.Length..], PipeDirection.Out);
    try
    {
        pipe.Connect(5000);
        return pipe;
    }
    catch
    {
        pipe.Dispose();
        throw;
    }
}

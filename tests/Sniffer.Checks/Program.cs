using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Sniffer.Core;
using Sniffer.Windows;

try
{
    string mode = args.FirstOrDefault() ?? "offline";
    switch (mode)
    {
        case "offline":
            Offline();
            break;
        case "live":
            await Live();
            break;
        case "tls":
            using (var keys = File.OpenText(args[3]))
            {
                var stream = new TlsStreamData(File.ReadAllBytes(args[1]), File.ReadAllBytes(args[2]), "", "");
                var inspection = TlsInspector.Inspect(stream, keys);
                Check(inspection.Status.Contains("认证失败 0") && inspection.Records.Any(row => row.Content.Contains("Certificate · 主体")),
                    inspection.Status);
                Check(inspection.ForwardText.Contains("sniffer-tls-request") && inspection.ReverseText.Contains("sniffer-tls-response"),
                    "verified TLS plaintext in both directions");
                stream.Reverse[^7] ^= 128;
                keys.BaseStream.Position = 0;
                keys.DiscardBufferedData();
                var corrupted = TlsInspector.Inspect(stream, keys);
                Check(corrupted.Records.Any(row => row.Content.Contains("认证失败")) &&
                    !corrupted.ReverseText.Contains("sniffer-tls-response"), "reject tampered TLS records");
                Console.WriteLine(inspection.Status + " · TLS certificate and application plaintext verified");
            }
            break;
        case "interfaces":
            Console.WriteLine(WindowsCapture.Version);
            foreach (var item in WindowsCapture.Interfaces()) Console.WriteLine($"{item.Id} | {item.Name}");
            break;
        case "sample":
            using (var stream = File.Create(args[1]))
            {
                var writer = new PcapWriter(stream, LinkType.Ethernet);
                foreach (RawPacket raw in DemoTrace.Read()) writer.Write(raw);
            }
            break;
        case "client":
            using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(12)))
            {
                if (args.Length > 4) await Task.Delay(int.Parse(args[4]), deadline.Token);
                string prefix = args.Length > 5 ? args[5] : "/child";
                await Task.WhenAll(Enumerable.Range(0, int.Parse(args[3])).Select(i =>
                    Client(IPAddress.Parse(args[1]), int.Parse(args[2]), $"{prefix}/{i}", deadline.Token)));
            }
            break;
        case "serve":
            using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25)))
            using (var listener = new TcpListener(IPAddress.Parse(args[1]), int.Parse(args[2])))
            {
                listener.Start();
                await Task.WhenAll(Enumerable.Range(0, int.Parse(args[3])).Select(_ => Serve(listener, deadline.Token)));
            }
            break;
        case "bench":
            await CaptureBenchmark.Run(args[1]);
            break;
        case "load":
            await CaptureBenchmark.Send(int.Parse(args[1]), int.Parse(args[2]));
            break;
        case "traffic":
            await DemoTraffic();
            break;
        case "ethernet":
            await Ethernet(args[1], IPAddress.Parse(args[2]), IPAddress.Parse(args[3]));
            break;
        default:
            throw new ArgumentException("Mode: offline | live | interfaces | sample <path> | traffic | bench <none|display|capture> | ethernet <interface-id> <source-ip> <gateway-ip>");
    }
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    return 1;
}

static void Offline()
{
    var preview = WindowsCapture.PreviewInterfaces();
    Check(preview.Count(item => item.Loopback) == 2 && preview.All(item => !string.IsNullOrWhiteSpace(item.Name)),
        "interface picker without administrator rights");
    RawPacket[] source = DemoTrace.Read().ToArray();
    using var pcap = new MemoryStream();
    var writer = new PcapWriter(pcap, LinkType.Ethernet);
    foreach (RawPacket raw in source) writer.Write(raw);
    pcap.Position = 0;
    RawPacket[] loaded = ClassicPcap.Read(pcap).ToArray();
    Check(loaded.Length == 23 && source.Zip(loaded).All(pair =>
        pair.First.Bytes.SequenceEqual(pair.Second.Bytes) && pair.First.WireLength == pair.Second.WireLength &&
        (pair.First.Timestamp - pair.Second.Timestamp).Duration().Ticks < 10), "PCAP round trip");

    var analysis = new LiveAnalysis();
    Packet[] packets = loaded.Select(raw => analysis.Decode(raw, false)).ToArray();
    Check(packets.SelectMany(packet => packet.DnsAddresses).Any(answer => answer.Name == "lab.example"),
        "DNS address names");
    var pairs = Connections.Summarize(packets, packets.Take(1).Select(packet => packet.Source!));
    Check(pairs.Sum(row => row.Incoming + row.Outgoing) == packets.Count(packet => packet.IpVersion > 0) &&
        pairs.Sum(row => row.BytesIn + row.BytesOut) == packets.Where(packet => packet.IpVersion > 0).Sum(packet => (long)packet.Raw.WireLength),
        "connection summary conserves counts and lengths");
    (string expression, int count)[] cases =
    [
        ("http", 2), ("tcp", 17), ("udp", 4), ("ipv4", 17), ("ipv6", 6), ("icmp", 1),
        ("icmpv6", 1), ("ipv6 && (tcp || icmpv6)", 5), ("tcp && !http", 15),
        ("dstport == 8080 && http", 1), ("ip.src == 2001:db8::1 && udp", 1),
        ("dns", 2), ("tls", 1), ("udp && !dns", 2)
    ];
    foreach (var (expression, expected) in cases)
        Check(packets.Count(DisplayFilter.Compile(expression)) == expected, $"display filter {expression}");
    CheckThrows<FormatException>(() => DisplayFilter.Compile("ipv6 && (tcp"), "invalid display expression");
    Check(packets[18].Dns == "查询 lab.example" && packets[19].Dns == "响应 lab.example → lab.example 192.0.2.20", "DNS query and answer");
    Check(packets[22].Tls == "ClientHello · TLS 1.2 · SNI: lab.example", "TLS ClientHello SNI");
    Check(packets.Count(DisplayFilter.CompileCapture("tcp port 8080 or udp dst port 5353")) == 16, "legacy capture filter syntax");
    Check(packets.Count(DisplayFilter.CompileCapture("ip6 && (tcp || icmp6)")) == 5, "capture filter aliases");
    Check(packets[5].Http == "GET /lab/packets HTTP/1.1 · Host: lab.local:8080", "HTTP split and out-of-order");
    Check(packets[6].Http == "HTTP/1.1 200 OK" && packets[12].Http is null, "HTTP response and port 8080 negative control");
    Check(packets[12].Layers.Any(layer => layer.Name.StartsWith("IPv6 扩展头")) &&
        packets[12].Tcp?.PayloadLength == 6, "IPv6 extension traversal");
    FlowSnapshot first = analysis.Flows.Find(packets[0].FlowId!.Value)!;
    Check(first.Packets == 10 && first.State == "双向 FIN" && first.Timeline.Count == 10 &&
        first.ForwardText.StartsWith("GET /lab/packets") && first.ForwardText.Split("GET").Length == 2 &&
        first.ReverseText.EndsWith("hello sniffer"), "bidirectional flow, retransmission, close");
    Check(packets.All(packet => packet.Owners.Count == 0), "offline does not invent process identities");

    RawPacket vlan = source[0] with { Bytes = new byte[source[0].Bytes.Length + 4], WireLength = source[0].WireLength + 4 };
    source[0].Bytes.AsSpan(0, 12).CopyTo(vlan.Bytes);
    new byte[] { 0x81, 0, 0, 42 }.CopyTo(vlan.Bytes, 12);
    source[0].Bytes.AsSpan(12).CopyTo(vlan.Bytes.AsSpan(16));
    Packet tagged = PacketDecoder.Decode(1, vlan);
    Check(tagged.Tcp is not null && tagged.Layers[1].Fields[0].Value == "42" &&
        tagged.Layers[2].Offset == 18, "VLAN field offset");

    RawPacket firstFragment = source[0] with { Bytes = source[0].Bytes.ToArray() };
    firstFragment.Bytes[20] = 0x20;
    Packet fragment = PacketDecoder.Decode(1, firstFragment);
    Check(fragment.Tcp is null && fragment.Note?.Contains("分片") == true, "IPv4 fragments");
    Packet truncated = PacketDecoder.Decode(1, source[3] with { Bytes = source[3].Bytes[..41] });
    Check(truncated.Tcp is null && truncated.Note?.Contains("截断") == true, "captured length bounds");

    foreach (RawPacket raw in source)
        for (int length = 0; length < raw.Bytes.Length; length++)
        {
            var shortPacket = PacketDecoder.Decode(1, raw with { Bytes = raw.Bytes[..length] });
            Check(shortPacket.Layers.All(layer => layer.Offset + layer.Length <= length), "truncation sweep");
        }

    var wrap = new LiveAnalysis();
    Packet syn = wrap.Decode(DemoTrace.Tcp(false, 59001, 8080, uint.MaxValue - 2, 0, 2, []), false);
    Packet gap = wrap.Decode(DemoTrace.Tcp(false, 59001, 8080, 0, 0, 24, "T /wrap HTTP/1.1\r\nHost: local\r\n\r\n"u8), false);
    Check(wrap.Flows.Find(gap.FlowId!.Value)!.ForwardStatus.Contains("缺口"), "sequence gap");
    Packet filled = wrap.Decode(DemoTrace.Tcp(false, 59001, 8080, uint.MaxValue - 1, 0, 24, "GE"u8), false);
    Check(syn.FlowId == filled.FlowId && filled.Http?.StartsWith("GET /wrap") == true, "sequence wrap");
    Packet reused = wrap.Decode(DemoTrace.Tcp(false, 59001, 8080, 500, 0, 2, []), false);
    Check(reused.FlowId != syn.FlowId, "endpoint reuse");
    var nullBytes = new byte[4 + source[0].Bytes.Length - 14];
    BinaryPrimitives.WriteUInt32LittleEndian(nullBytes, 2);
    source[0].Bytes.AsSpan(14).CopyTo(nullBytes.AsSpan(4));
    Packet loopback = PacketDecoder.Decode(1, source[0] with { Link = LinkType.Null, Bytes = nullBytes, WireLength = (uint)nullBytes.Length });
    Check(loopback.Tcp?.Destination.Port == 8080 && loopback.Layers[1].Offset == 4, "DLT_NULL");

    RawPacket rawIp = source[0] with { Link = LinkType.RawIp, Bytes = source[0].Bytes[14..], WireLength = source[0].WireLength - 14 };
    using var rawFile = new MemoryStream();
    new PcapWriter(rawFile, LinkType.RawIp).Write(rawIp);
    rawFile.Position = 0;
    Packet rawDecoded = PacketDecoder.Decode(1, ClassicPcap.Read(rawFile).Single());
    Check(rawDecoded.Layers[0].Offset == 0 && rawDecoded.Tcp?.Destination.Port == 8080, "raw IP PCAP round trip");

    using var broken = new MemoryStream(pcap.ToArray()[..^1]);
    CheckThrows<InvalidDataException>(() => ClassicPcap.Read(broken).ToArray(), "truncated PCAP rejected");

    using var pcapng = new MemoryStream();
    WritePcapNgFixture(pcapng, source, little: true);
    WritePcapNgFixture(pcapng, source, little: false);
    pcapng.Position = 0;
    RawPacket[] fromNg = CaptureFile.Read(pcapng).ToArray();
    Check(fromNg.Length == source.Length * 2 && source.Concat(source).Zip(fromNg).All(pair =>
        pair.First.Bytes.SequenceEqual(pair.Second.Bytes) && pair.First.Link == pair.Second.Link &&
        (pair.First.Timestamp - pair.Second.Timestamp).Duration().Ticks < 10), "PCAPNG mixed-endian sections");
    using var ngExport = new MemoryStream();
    var earlier = rawIp with { Timestamp = DateTimeOffset.UnixEpoch.AddTicks(-125) };
    PcapNg.Write(ngExport, [source[0], earlier]);
    ngExport.Position = 0;
    RawPacket[] mixed = CaptureFile.Read(ngExport).ToArray();
    Check(mixed.Length == 2 && mixed[0].Link == LinkType.Ethernet && mixed[1].Link == LinkType.RawIp &&
        mixed[1].Timestamp == earlier.Timestamp && mixed[1].Bytes.SequenceEqual(earlier.Bytes), "mixed-link PCAPNG export");
    using var brokenNg = new MemoryStream(ngExport.ToArray()[..^1]);
    CheckThrows<InvalidDataException>(() => CaptureFile.Read(brokenNg).ToArray(), "truncated PCAPNG rejected");
    pcap.Position = 0;
    Check(CaptureFile.Read(pcap).Count() == source.Length, "capture file detects classic PCAP");

    var keepAlive = new LiveAnalysis();
    byte[] firstRequest = "GET /one HTTP/1.1\r\nHost: lab.local\r\nContent-Length: 0\r\n\r\n"u8.ToArray();
    byte[] secondRequest = "GET /two HTTP/1.1\r\nHost: lab.local\r\nContent-Length: 0\r\n\r\n"u8.ToArray();
    Packet opening = keepAlive.Decode(DemoTrace.Tcp(false, 49800, 80, 1, 0, 24, firstRequest), false);
    Packet pipelined = keepAlive.Decode(DemoTrace.Tcp(false, 49800, 80, 1 + (uint)firstRequest.Length, 0, 24, secondRequest), false);
    Check(opening.Http == "GET /one HTTP/1.1 · Host: lab.local" &&
        pipelined.Http == "GET /two HTTP/1.1 · Host: lab.local" && opening.FlowId == pipelined.FlowId, "keep-alive second request");

    var http = new LiveAnalysis();
    http.Decode(DemoTrace.Tcp(false, 49801, 80, 1, 0, 24,
        "HEAD /one HTTP/1.1\r\nHost: lab\r\n\r\nGET /two HTTP/1.1\r\nHost: lab\r\n\r\n"u8), false);
    Packet responses = http.Decode(DemoTrace.Tcp(false, 80, 49801, 10, 0, 24,
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"u8,
        reverse: true), false);
    Check(responses.Http == "HTTP/1.1 100 Continue | HTTP/1.1 200 OK | HTTP/1.1 204 No Content",
        "informational and HEAD responses preserve framing");
    Packet chunked = http.Decode(DemoTrace.Tcp(false, 49802, 80, 1, 0, 24,
        "POST /chunk HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-One: a\r\nX-Two: b\r\n\r\nGET /next HTTP/1.1\r\n\r\n"u8), false);
    Check(chunked.Http == "POST /chunk HTTP/1.1 | GET /next HTTP/1.1", "chunked trailers preserve next message");

    var owned = new LiveAnalysis();
    var owner = new ProcessOwner(new Endpoint(IPAddress.Parse("192.0.2.10"), 49900), 4242, "lab", null);
    Packet early = owned.Decode(DemoTrace.Tcp(false, 49900, 80, 10, 0, 2, []), false);
    Packet discovered = PacketDecoder.Decode(2, DemoTrace.Tcp(false, 49900, 80, 11, 0, 16, []));
    owned.Flows.Observe(discovered, [owner]);
    Packet later = owned.Decode(DemoTrace.Tcp(false, 49900, 80, 11, 0, 16, []), false);
    Check(early.Owners.Single().Pid == 4242 && later.Owners.Single().Pid == 4242 &&
        owned.Flows.ConsumeOwnersChanged(), "session ownership backfills earlier packets");

    Console.WriteLine("PASS: PCAP/PCAPNG; Ethernet/VLAN/Loopback; IPv4/IPv6/ICMP/TCP/UDP/DNS/TLS; filters; bounded parsing; HTTP and TCP reassembly.");
}

static async Task Live()
{
    var interfaces = WindowsCapture.Interfaces();
    CaptureInterface loopback = interfaces.Single(item => item.Id == "loopback-v4");
    CaptureInterface loopback6 = interfaces.Single(item => item.Id == "loopback-v6");
    Console.WriteLine(WindowsCapture.Version);
    CheckThrows<FormatException>(() => new WindowsCapture(loopback, "tcp && unknown)"), "reject invalid capture filter");
    CheckThrows<FormatException>(() => new WindowsCapture(loopback, "http"), "HTTP is a display filter");
    await VerifyIdleStop(loopback);

    await VerifyLiveTcp(loopback, IPAddress.Loopback, true);
    await VerifyIdleStop(loopback6);
    await VerifyLiveTcp(loopback6, IPAddress.IPv6Loopback, true);
    await VerifyLiveIPv6Datagrams(loopback6);

    using var stop = new CancellationTokenSource();
    var capture = new WindowsCapture(loopback, "icmp or udp dst port 46071");
    var packets = new List<Packet>();
    var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    Task running = Task.Run(() => capture.Run(packets.Add, _ => { }, stop.Token, () => started.SetResult()));
    try
    {
        await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await SendDatagrams();
        await Task.Delay(300);
    }
    finally
    {
        stop.Cancel();
        await running.WaitAsync(TimeSpan.FromSeconds(4));
    }
    foreach (string filter in new[] { "icmp", "udp && ipv4" })
        Check(packets.Any(DisplayFilter.Compile(filter)), $"live {filter}");
    Console.WriteLine("PASS: live IPv4 loopback UDP and ICMP.");
}

static async Task VerifyLiveIPv6Datagrams(CaptureInterface loopback)
{
    using var receiver = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
    int port = ((IPEndPoint)receiver.Client.LocalEndPoint!).Port;
    using var stop = new CancellationTokenSource();
    var capture = new WindowsCapture(loopback, $"icmp6 or udp dst port {port}");
    var packets = new List<Packet>();
    var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    Task running = Task.Run(() => capture.Run(packets.Add, _ => { }, stop.Token, () => started.SetResult()));
    try
    {
        await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        using var sender = new UdpClient(AddressFamily.InterNetworkV6);
        await sender.SendAsync("sniffer-ipv6"u8.ToArray(), new IPEndPoint(IPAddress.IPv6Loopback, port));
        using var ping = new Ping();
        await ping.SendPingAsync(IPAddress.IPv6Loopback, 2000);
        await Task.Delay(250);
    }
    finally
    {
        stop.Cancel();
        await running.WaitAsync(TimeSpan.FromSeconds(4));
    }
    Check(packets.Any(packet => packet.IpVersion == 6 && packet.IpProtocol == 17) &&
        packets.Any(packet => packet.IpVersion == 6 && packet.IpProtocol == 58), "IPv6 loopback UDP and ICMPv6");
    Console.WriteLine("PASS: live IPv6 loopback UDP and ICMPv6.");
}

static async Task VerifyLiveTcp(CaptureInterface loopback, IPAddress ip, bool testEvents = false)
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    using var stopCapture = new CancellationTokenSource();
    using var listener = new TcpListener(ip, 0);
    listener.Start();
    int port = ((IPEndPoint)listener.LocalEndpoint).Port;

    var analysis = new LiveAnalysis();
    using var ownership = testEvents ? analysis.TrackSockets() : null;
    if (testEvents) Check(ownership is not null, analysis.SocketEventsUnavailable ?? "socket events started");
    var packets = new List<Packet>();
    CaptureStatistics? stats = null;
    var capture = new WindowsCapture(loopback, $"tcp and port {port}");
    var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    Task capturing = Task.Run(() => capture.Run(packet =>
    {
        if (!testEvents) analysis.Observe(packet, true);
        packets.Add(packet);
    }, value => stats = value, stopCapture.Token, () => started.SetResult()));
    await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
    using var child = StartClients(ip, port, 2);
    Task[] servers = Enumerable.Range(0, 3).Select(_ => Serve(listener, deadline.Token)).ToArray();
    try
    {
        await Client(ip, port, "/parent", deadline.Token);
        await Task.WhenAll(servers).WaitAsync(deadline.Token);
        await child.WaitForExitAsync(deadline.Token);
        Check(child.ExitCode == 0, "traffic child exited successfully");
        await Task.Delay(testEvents ? 2300 : 300, deadline.Token);
    }
    finally
    {
        stopCapture.Cancel();
        await capturing.WaitAsync(TimeSpan.FromSeconds(4));
        if (!child.HasExited) child.Kill();
    }

    if (testEvents)
        foreach (Packet packet in packets)
            analysis.Observe(packet, true);
    Check(capture.Link == LinkType.RawIp && packets.Count >= 12 && packets.All(packet => packet.Tcp is not null &&
        (packet.SourcePort == port || packet.DestinationPort == port)), "live filter and raw IP");
    var flows = analysis.Flows.List();
    FlowSnapshot[] childFlows = flows.Where(flow => flow.Owners.Any(owner => owner.Pid == child.Id)).ToArray();
    Check(flows.Count == 3 && childFlows.Length == 2, $"live PID isolation: total={flows.Count}, child={childFlows.Length}, " +
        string.Join(" | ", flows.Select(flow => $"{flow.Endpoints} {flow.Processes}")));
    Check(packets.Any(packet => packet.Http?.Contains("GET /child/") == true) &&
        packets.Any(packet => packet.Http?.Contains("GET /parent") == true) &&
        packets.Any(packet => packet.Http == "HTTP/1.1 200 OK"), "live HTTP request/response");
    Check(childFlows.All(flow => flow.Owners.Any(owner => owner.Pid == Environment.ProcessId)), "both loopback process endpoints");
    Check(packets.Count(DisplayFilter.Compile($"pid == {child.Id}")) > 0, "display filter by PID");
    Console.WriteLine($"PASS: {ip}; {packets.Count} packets; {flows.Count} TCP sessions; child PID {child.Id} matched {childFlows.Length}; received before filtering={stats?.Received}.");
    if (testEvents) Console.WriteLine("PASS: socket events preserve owners after short connections leave the TCP table.");
}

static async Task VerifyIdleStop(CaptureInterface loopback)
{
    for (int i = 0; i < 2; i++)
    {
        using var stop = new CancellationTokenSource();
        var capture = new WindowsCapture(loopback, "tcp and port 1");
        Task running = Task.Run(() => capture.Run(_ => { }, _ => { }, stop.Token));
        await Task.Delay(250);
        stop.Cancel();
        await running.WaitAsync(TimeSpan.FromSeconds(3));
    }
    Console.WriteLine("PASS: idle capture cancellation and restart.");
}

static async Task Ethernet(string id, IPAddress source, IPAddress gateway)
{
    CaptureInterface adapter = WindowsCapture.Interfaces().Single(item => item.Id == id || item.Name.Split(" · ")[0] == id);
    IPAddress peer = new(gateway.GetAddressBytes());
    IPAddress local = new(source.GetAddressBytes());
    string protocol = local.AddressFamily == AddressFamily.InterNetwork ? "icmp" : "icmp6";
    var capture = new WindowsCapture(adapter, $"{protocol} and host {local} and host {peer}");
    using var stop = new CancellationTokenSource();
    var packets = new List<Packet>();
    var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    Task running = Task.Run(() => capture.Run(packets.Add, _ => { }, stop.Token, () => started.SetResult()));
    try
    {
        await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        using var ping = new Ping();
        await ping.SendPingAsync(gateway, 1200, "sniffer-lab"u8.ToArray());
        await Task.Delay(300);
    }
    finally
    {
        stop.Cancel();
        await running.WaitAsync(TimeSpan.FromSeconds(4));
    }
    Check(capture.Link == LinkType.Ethernet && packets.Any(packet => packet.Source?.Equals(local) == true &&
        packet.Destination?.Equals(peer) == true && packet.IpProtocol == (protocol == "icmp" ? 1 : 58)), "live Ethernet ICMP");
    Console.WriteLine($"PASS: real DLT_EN10MB adapter; {packets.Count} filtered {protocol} packets.");
}

static async Task DemoTraffic()
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(50));
    using var v4 = new TcpListener(IPAddress.Loopback, 8080);
    using var v6 = new TcpListener(IPAddress.IPv6Loopback, 8080);
    v4.Start();
    v6.Start();
    for (int i = 0; i < 5; i++)
    {
        using var child = StartClients(IPAddress.Loopback, 8080, 2);
        Console.WriteLine($"Round {i + 1}: PID {child.Id} creates 2 IPv4 sessions. PID {Environment.ProcessId} creates 1 IPv6 session.");
        Task serve = Task.WhenAll(Serve(v4, deadline.Token), Serve(v4, deadline.Token), Serve(v6, deadline.Token));
        await Task.WhenAll(serve, Client(IPAddress.IPv6Loopback, 8080, "/parent", deadline.Token), SendDatagrams());
        await child.WaitForExitAsync(deadline.Token);
        Check(child.ExitCode == 0, "demo client exited");
        await Task.Delay(1800, deadline.Token);
    }
}

static async Task SendDatagrams()
{
    foreach (IPAddress ip in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
    {
        using var receiver = new UdpClient(new IPEndPoint(ip, 46071));
        using var sender = new UdpClient(ip.AddressFamily);
        await sender.SendAsync("sniffer-udp"u8.ToArray(), new IPEndPoint(ip, 46071));
        using var ping = new Ping();
        await ping.SendPingAsync(ip, 1000, "sniffer-icmp"u8.ToArray());
    }
}

static Process StartClients(IPAddress ip, int port, int count)
{
    string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Process path unavailable.");
    var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
    if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        info.ArgumentList.Add(typeof(Program).Assembly.Location);
    foreach (string arg in new[] { "client", ip.ToString(), port.ToString(), count.ToString() })
        info.ArgumentList.Add(arg);
    return Process.Start(info) ?? throw new InvalidOperationException("Failed to start test client.");
}

static async Task Client(IPAddress ip, int port, string path, CancellationToken cancellation)
{
    using var client = new TcpClient(ip.AddressFamily) { NoDelay = true };
    await client.ConnectAsync(ip, port, cancellation);
    using NetworkStream stream = client.GetStream();
    await stream.WriteAsync("GET "u8.ToArray(), cancellation);
    await Task.Delay(240, cancellation);
    await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes($"{path} HTTP/1.1\r\nHost: localhost\r\n\r\n"), cancellation);
    await stream.ReadExactlyAsync(new byte[40], cancellation);
    await Task.Delay(260, cancellation);
}

static async Task Serve(TcpListener listener, CancellationToken cancellation)
{
    using TcpClient client = await listener.AcceptTcpClientAsync(cancellation);
    using NetworkStream stream = client.GetStream();
    var bytes = new byte[4096];
    int received = 0;
    do
    {
        int count = await stream.ReadAsync(bytes.AsMemory(received), cancellation);
        if (count == 0) throw new IOException("Demo HTTP request incomplete.");
        received += count;
    }
    while (bytes.AsSpan(0, received).IndexOf("\r\n\r\n"u8) < 0 && received < bytes.Length);
    await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"u8.ToArray(), cancellation);
    await Task.Delay(300, cancellation);
}

static void WritePcapNgFixture(Stream stream, IReadOnlyList<RawPacket> packets, bool little)
{
    void Put32(Span<byte> data, uint value)
    {
        if (little) BinaryPrimitives.WriteUInt32LittleEndian(data, value);
        else BinaryPrimitives.WriteUInt32BigEndian(data, value);
    }

    void Block(uint type, ReadOnlySpan<byte> body)
    {
        int total = 12 + ((body.Length + 3) & ~3);
        var block = new byte[total];
        Put32(block, type);
        Put32(block.AsSpan(4), (uint)total);
        body.CopyTo(block.AsSpan(8));
        Put32(block.AsSpan(total - 4), (uint)total);
        stream.Write(block);
    }

    var section = new byte[16];
    Put32(section, 0x1a2b3c4d);
    section[little ? 4 : 5] = 1;
    section.AsSpan(8).Fill(0xff);
    Block(0x0a0d0d0a, section);

    var iface = new byte[8];
    iface[little ? 0 : 1] = (byte)LinkType.Ethernet;
    Put32(iface.AsSpan(4), ClassicPcap.MaxFrame);
    Block(1, iface);

    foreach (RawPacket packet in packets)
    {
        var body = new byte[20 + packet.Bytes.Length];
        long micros = packet.Timestamp.ToUnixTimeMilliseconds() * 1000 +
            packet.Timestamp.UtcTicks % TimeSpan.TicksPerMillisecond / 10;
        Put32(body.AsSpan(4), (uint)(micros >> 32));
        Put32(body.AsSpan(8), (uint)micros);
        Put32(body.AsSpan(12), (uint)packet.Bytes.Length);
        Put32(body.AsSpan(16), packet.WireLength);
        packet.Bytes.CopyTo(body, 20);
        Block(6, body);
    }
}

static void Check(bool ok, string label)
{
    if (!ok) throw new InvalidOperationException($"FAIL: {label}");
}

static void CheckThrows<T>(Action action, string label) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"FAIL: {label}");
}

using System.Collections;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Sniffer.Core;

public sealed record FlowEvent(long PacketNumber, double Milliseconds, string Direction, string Flags,
    uint Sequence, uint Acknowledgment, int Bytes, string Application);

public sealed record FlowSnapshot(long Id, Endpoint A, Endpoint B, DateTimeOffset First, DateTimeOffset Last,
    string State, long Packets, long Bytes, IReadOnlyList<ProcessOwner> Owners,
    string ForwardText, string ReverseText, string ForwardStatus, string ReverseStatus, IReadOnlyList<FlowEvent> Timeline)
{
    public string Endpoints => $"{A} ↔ {B}";
    public string Processes => Owners.Count == 0 ? "未知" : string.Join(" / ", Owners.Select(owner => owner.Label).Distinct());
    public string Duration => $"{(Last - First).TotalSeconds:F2} s";
}

public sealed class FlowTracker
{
    private const int MaxFlows = 1024;
    private const int MaxEvents = 160;
    private static readonly TimeSpan Idle = TimeSpan.FromMinutes(2);
    private readonly Dictionary<(Endpoint, Endpoint), Flow> _current = [];
    private readonly Dictionary<long, Flow> _history = [];
    private readonly Queue<Flow> _order = new();
    private long _nextId;
    private int _ownersChanged;
    private readonly object _gate = new();

    /// <summary>True once since the last call when a session learned a process owner and earlier packets of that
    /// session were updated. The UI re-filters so those packets become selectable by PID.</summary>
    public bool ConsumeOwnersChanged() => Interlocked.Exchange(ref _ownersChanged, 0) != 0;

    public void Observe(Packet packet, IReadOnlyList<ProcessOwner>? owners = null)
    {
        if (packet.Tcp is not { } tcp)
            return;
        lock (_gate)
        {
            var key = Pair(tcp.Source, tcp.Destination);
            bool newSyn = tcp.Syn && !tcp.Ack;
            if (!_current.TryGetValue(key, out Flow? flow) || packet.Raw.Timestamp - flow.Last > Idle ||
                (newSyn && (flow.Closed || flow.FirstSyn != tcp.Sequence || flow.A != tcp.Source)))
            {
                flow = new Flow(++_nextId, tcp.Source, tcp.Destination, packet.Raw.Timestamp, newSyn ? tcp.Sequence : null);
                _current[key] = flow;
                _history.Add(flow.Id, flow);
                _order.Enqueue(flow);
                if (_order.Count > MaxFlows)
                {
                    Flow expired = _order.Dequeue();
                    _history.Remove(expired.Id);
                    var expiredKey = Pair(expired.A, expired.B);
                    if (_current.GetValueOrDefault(expiredKey) == expired)
                        _current.Remove(expiredKey);
                }
            }

            bool forward = tcp.Source == flow.A;
            Reassembly direction = forward ? flow.Forward : flow.Reverse;
            Reassembly other = forward ? flow.Reverse : flow.Forward;
            packet.FlowId = flow.Id;
            direction.Append(tcp, packet.Raw.Bytes.AsSpan(tcp.PayloadOffset, tcp.PayloadLength), other);
            ApplyMessages(packet, tcp, direction.Completed);
            flow.Last = packet.Raw.Timestamp;
            flow.Packets++;
            flow.Bytes += tcp.PayloadLength;
            flow.HandshakeComplete |= tcp.Ack && !tcp.Syn && flow.Forward.SawSyn && flow.Reverse.SawSyn;
            flow.Reset |= tcp.Rst;
            flow.ForwardFin |= forward && tcp.Fin;
            flow.ReverseFin |= !forward && tcp.Fin;

            packet.SessionOwners = flow.SharedOwners;
            foreach (ProcessOwner owner in owners ?? []) PublishOwner(flow, owner);

            if (flow.Events.Count == MaxEvents) flow.Events.Dequeue();
            flow.Events.Enqueue(new FlowEvent(packet.Number, (packet.Raw.Timestamp - flow.First).TotalMilliseconds,
                forward ? "A → B" : "B → A", tcp.FlagNames, tcp.Sequence, tcp.Acknowledgment, tcp.PayloadLength,
                packet.Http ?? packet.Tls ?? ""));
        }
    }

    public void AssociateOwner(ProcessOwner owner, Endpoint remote, DateTimeOffset timestamp)
    {
        lock (_gate)
        {
            if (!_current.TryGetValue(Pair(owner.Local, remote), out Flow? flow) ||
                timestamp < flow.First.AddMilliseconds(-100) || timestamp > flow.Last.AddSeconds(1))
                return;
            PublishOwner(flow, owner);
        }
    }

    private void PublishOwner(Flow flow, ProcessOwner owner)
    {
        if (!flow.Owners.TryAdd(owner.Local, owner)) return;
        flow.SharedOwners.Publish(flow.Owners.Values.ToArray());
        Interlocked.Exchange(ref _ownersChanged, 1);
    }

    private static void ApplyMessages(Packet packet, TcpSegment tcp, List<StreamMessage> messages)
    {
        if (messages.Count == 0) return;
        int segmentStart = tcp.PayloadOffset;
        var http = new List<string>();
        var tls = new List<string>();
        foreach (StreamMessage message in messages)
        {
            int overlap = Math.Min(message.End, segmentStart + tcp.PayloadLength) - Math.Max(message.Start, segmentStart);
            int offset = overlap > 0 ? message.Start < segmentStart ? segmentStart : message.Start : segmentStart;
            int length = Math.Max(0, overlap);
            packet.DecodedLayers.Add(new PacketLayer(message.LayerName, offset, length,
                [new PacketField(message.FieldName, message.Summary, offset, length)]));
            (message.Protocol == "HTTP" ? http : tls).Add(message.Summary);
        }
        if (http.Count > 0) packet.Http = string.Join(" | ", http);
        if (tls.Count > 0) packet.Tls = string.Join(" | ", tls);
    }

    public FlowSnapshot? Find(long id)
    {
        lock (_gate)
            return _history.TryGetValue(id, out Flow? flow) ? flow.Snapshot() : null;
    }

    public TlsStreamData? ReadTlsStream(long id)
    {
        lock (_gate)
            return _history.TryGetValue(id, out Flow? flow)
                ? new TlsStreamData(flow.Forward.Bytes(), flow.Reverse.Bytes(), flow.Forward.Status, flow.Reverse.Status) : null;
    }

    public IReadOnlyList<FlowSnapshot> List(int? pid = null)
    {
        lock (_gate)
            return _history.Values.Reverse()
                .Where(flow => pid is null || flow.Owners.Values.Any(owner => owner.Pid == pid))
                .Select(flow => flow.Snapshot(includeData: false)).ToArray();
    }

    private static (Endpoint, Endpoint) Pair(Endpoint a, Endpoint b)
    {
        int order = a.Address.GetAddressBytes().AsSpan().SequenceCompareTo(b.Address.GetAddressBytes());
        if (order == 0) order = a.Address.AddressFamily.CompareTo(b.Address.AddressFamily);
        if (order == 0 && a.Address.AddressFamily == AddressFamily.InterNetworkV6)
            order = a.Address.ScopeId.CompareTo(b.Address.ScopeId);
        if (order == 0) order = a.Port.CompareTo(b.Port);
        return order <= 0 ? (a, b) : (b, a);
    }

    private sealed class Flow(long id, Endpoint a, Endpoint b, DateTimeOffset first, uint? firstSyn)
    {
        public long Id { get; } = id;
        public Endpoint A { get; } = a;
        public Endpoint B { get; } = b;
        public DateTimeOffset First { get; } = first;
        public uint? FirstSyn { get; } = firstSyn;
        public DateTimeOffset Last { get; set; } = first;
        public long Packets { get; set; }
        public long Bytes { get; set; }
        public bool ForwardFin { get; set; }
        public bool ReverseFin { get; set; }
        public bool Reset { get; set; }
        public bool HandshakeComplete { get; set; }
        public bool Closed => Reset || ForwardFin && ReverseFin;
        public Reassembly Forward { get; } = new();
        public Reassembly Reverse { get; } = new();
        public Queue<FlowEvent> Events { get; } = new();
        public Dictionary<Endpoint, ProcessOwner> Owners { get; } = [];
        public FlowOwners SharedOwners { get; } = new();

        public FlowSnapshot Snapshot(bool includeData = true) => new(Id, A, B, First, Last,
            Reset ? "RST" : Closed ? "双向 FIN" : ForwardFin || ReverseFin ? "半关闭" :
            HandshakeComplete ? "已握手" : FirstSyn is null ? "中途捕获" : "握手中",
            Packets, Bytes, Owners.Values.ToArray(), includeData ? Forward.Text : "", includeData ? Reverse.Text : "",
            Forward.Status, Reverse.Status, includeData ? Events.ToArray() : []);
    }

    /// <summary>A recognised application message and where it sits in this packet's captured bytes.</summary>
    private sealed record StreamMessage(string Protocol, string Summary, string LayerName, string FieldName, int Start, int End);

    private sealed class Reassembly
    {
        private const int Limit = 32_768;
        private readonly List<byte> _prefix = [];
        private byte[]? _pending;
        private BitArray? _present;
        private int _pendingCount;
        private uint? _base;
        private bool _limited;
        private bool _truncated;
        private readonly HttpStream _http = new();
        private readonly TlsStream _tls = new();

        public bool SawSyn { get; private set; }
        public byte[] Bytes() => _prefix.ToArray();
        public List<StreamMessage> Completed { get; } = [];
        public string Text => string.Create(_prefix.Count, _prefix, (text, bytes) =>
        {
            for (int i = 0; i < bytes.Count; i++)
            {
                byte value = bytes[i];
                text[i] = value is 9 or 10 or 13 or >= 32 and < 127 ? (char)value : '·';
            }
        });

        public string Status => string.Join(" · ", new[]
        {
            _pendingCount > 0 ? "存在序列号缺口" : null,
            _truncated ? "曾有截断段" : null,
            _base is not null && !SawSyn ? "从首个可见数据段开始" : null,
            _limited ? "达到重组上限" : null
        }.OfType<string>());

        public void Append(TcpSegment tcp, ReadOnlySpan<byte> bytes, Reassembly other)
        {
            Completed.Clear();
            uint dataSequence = unchecked(tcp.Sequence + (tcp.Syn ? 1u : 0u));
            if (tcp.Syn)
            {
                SawSyn = true;
                _base ??= dataSequence;
            }
            _truncated |= tcp.PayloadTruncated;
            if (bytes.IsEmpty)
                return;

            _base ??= dataSequence;
            int offset = unchecked((int)(dataSequence - _base.Value));
            int segmentOffset = offset;
            if (offset < 0)
            {
                if (offset <= -bytes.Length) return;
                bytes = bytes[-offset..];
                offset = 0;
            }
            if (offset >= Limit)
            {
                _limited = true;
                return;
            }
            if (bytes.Length > Limit - offset)
            {
                _limited = true;
                bytes = bytes[..(Limit - offset)];
            }
            if (offset + bytes.Length <= _prefix.Count) return;

            int before = _prefix.Count;
            if (offset <= before)
            {
                for (int index = before; index < offset + bytes.Length; index++)
                    _prefix.Add(_present?[index] == true ? TakePending(index) : bytes[index - offset]);
                while (_prefix.Count < Limit && _present?[_prefix.Count] == true)
                    _prefix.Add(TakePending(_prefix.Count));
                if (_pendingCount == 0)
                {
                    _pending = null;
                    _present = null;
                }
            }
            else
            {
                _pending ??= new byte[Limit];
                _present ??= new BitArray(Limit);
                for (int i = 0; i < bytes.Length; i++)
                {
                    int index = offset + i;
                    if (_present[index]) continue;
                    _pending[index] = bytes[i];
                    _present[index] = true;
                    _pendingCount++;
                }
            }

            if (_prefix.Count <= before) return;
            var data = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_prefix);
            foreach (StreamMessage message in _http.Scan(data, other._http))
                Completed.Add(message with { Start = InPacket(message.Start, segmentOffset, tcp), End = InPacket(message.End, segmentOffset, tcp) });
            if (_http.Stopped)
                foreach (StreamMessage message in _tls.Scan(data))
                    Completed.Add(message with { Start = InPacket(message.Start, segmentOffset, tcp), End = InPacket(message.End, segmentOffset, tcp) });

            int InPacket(int streamPosition, int segmentOffset, TcpSegment segment)
            {
                long delta = (long)streamPosition - segmentOffset;
                if (delta < 0) return segment.PayloadOffset;
                if (delta > segment.PayloadLength) return segment.PayloadOffset + segment.PayloadLength;
                return segment.PayloadOffset + (int)delta;
            }
        }

        private byte TakePending(int offset)
        {
            _present![offset] = false;
            _pendingCount--;
            return _pending![offset];
        }
    }

    /// <summary>Reads HTTP/1.x messages one after another from a direction's contiguous bytes, so a keep-alive
    /// connection yields every request and response instead of only the first.</summary>
    private sealed class HttpStream
    {
        private const int Limit = 16_384;
        private const int MaxLine = 4096;
        private enum Phase { Start, Headers, Body, ChunkSize, ChunkData, ChunkDelim, Trailers, Stopped }
        private Phase _phase = Phase.Start;
        private int _cursor;
        private int _messageStart;
        private long _bodyLeft;
        private bool _chunked;
        private int _status;
        private string _method = "";
        private long _contentLength = -1;
        private string _summary = "";
        private readonly Queue<string> _requests = new();

        public bool Stopped => _phase == Phase.Stopped;

        public List<StreamMessage> Scan(ReadOnlySpan<byte> data, HttpStream peer)
        {
            var found = new List<StreamMessage>();
            int guard = 0;
            while (_phase != Phase.Stopped && _cursor < data.Length && guard++ < 100_000)
            {
                switch (_phase)
                {
                    case Phase.Start:
                        if (data[_cursor] is < 32 or >= 127) { _phase = Phase.Stopped; break; }
                        int lineEnd = FindCrlf(data, _cursor);
                        if (lineEnd < 0) { if (data.Length - _cursor > MaxLine) _phase = Phase.Stopped; return found; }
                        if (!TryStartLine(data[_cursor..lineEnd], out _status, out _method, out string summary)) { _phase = Phase.Stopped; break; }
                        _messageStart = _cursor;
                        _summary = summary;
                        _chunked = false;
                        _contentLength = -1;
                        _cursor = lineEnd + 2;
                        _phase = Phase.Headers;
                        break;

                    case Phase.Headers:
                        int headerEnd = FindCrlf(data, _cursor);
                        if (headerEnd < 0) { if (data.Length - _cursor > MaxLine) _phase = Phase.Stopped; return found; }
                        if (headerEnd == _cursor)
                        {
                            _cursor += 2;
                            found.Add(new StreamMessage("HTTP", _summary, "HTTP/1.x（TCP 连续字节）", "起始行及关键头部",
                                _messageStart, _cursor));
                            _phase = NextPhase(peer);
                            if (_phase == Phase.Body) _bodyLeft = _contentLength;
                            break;
                        }
                        if (!TryHeader(data[_cursor..headerEnd], ref _summary, ref _chunked, ref _contentLength)) { _phase = Phase.Stopped; break; }
                        _cursor = headerEnd + 2;
                        break;

                    case Phase.Body:
                        int take = (int)Math.Min(_bodyLeft, data.Length - _cursor);
                        _cursor += take;
                        _bodyLeft -= take;
                        if (_bodyLeft > 0) return found;
                        _phase = Phase.Start;
                        break;

                    case Phase.ChunkSize:
                        int sizeEnd = FindCrlf(data, _cursor);
                        if (sizeEnd < 0) return found;
                        if (!TryChunkSize(data[_cursor..sizeEnd], out long size)) { _phase = Phase.Stopped; break; }
                        _cursor = sizeEnd + 2;
                        if (size == 0) { _phase = Phase.Trailers; break; }
                        _bodyLeft = size;
                        _phase = Phase.ChunkData;
                        break;

                    case Phase.ChunkData:
                        int chunk = (int)Math.Min(_bodyLeft, data.Length - _cursor);
                        _cursor += chunk;
                        _bodyLeft -= chunk;
                        if (_bodyLeft > 0) return found;
                        _phase = Phase.ChunkDelim;
                        break;

                    case Phase.ChunkDelim:
                        if (data.Length - _cursor < 2) return found;
                        if (data[_cursor] != '\r' || data[_cursor + 1] != '\n') { _phase = Phase.Stopped; break; }
                        _cursor += 2;
                        _phase = Phase.ChunkSize;
                        break;

                    case Phase.Trailers:
                        int trailerEnd = FindCrlf(data, _cursor);
                        if (trailerEnd < 0) return found;
                        if (trailerEnd == _cursor) _phase = Phase.Start;
                        _cursor = trailerEnd + 2;
                        break;
                }
            }
            return found;
        }

        private Phase NextPhase(HttpStream peer)
        {
            if (_status == 0)
            {
                if (_requests.Count < 128) _requests.Enqueue(_method);
            }
            else
            {
                peer._requests.TryPeek(out string? request);
                if (_status == 101 || _status >= 200) peer._requests.TryDequeue(out _);
                if (_status == 101 || request == "CONNECT" && _status is >= 200 and < 300)
                {
                    peer._phase = Phase.Stopped;
                    return Phase.Stopped;
                }
                if (_status < 200 || _status is 204 or 304 || request == "HEAD") return Phase.Start;
            }
            if (_chunked) return Phase.ChunkSize;
            if (_contentLength > 0) return Phase.Body;
            return _status != 0 && _contentLength < 0 ? Phase.Stopped : Phase.Start;
        }

        private static int FindCrlf(ReadOnlySpan<byte> data, int from)
        {
            int relative = data[from..].IndexOf("\r\n"u8);
            return relative < 0 ? -1 : from + relative;
        }

        private static bool TryStartLine(ReadOnlySpan<byte> line, out int status, out string method, out string summary)
        {
            status = 0;
            method = "";
            summary = "";
            if (line.Length == 0 || line.Length > MaxLine || !Printable(line)) return false;
            string text = Encoding.ASCII.GetString(line);
            string[] parts = text.Split(' ', 3);
            if (parts.Length != 3) return false;
            bool request = IsToken(parts[0]) && parts[1].Length > 0 && parts[1].All(c => c > ' ' && c < '\u007f') && IsVersion(parts[2]);
            bool response = IsVersion(parts[0]) && parts[1].Length == 3 && parts[1][0] is >= '1' and <= '5' && parts[1].All(char.IsAsciiDigit);
            if (!request && !response) return false;
            if (response) status = int.Parse(parts[1], CultureInfo.InvariantCulture);
            else method = parts[0];
            summary = text;
            return true;
        }

        private static bool TryHeader(ReadOnlySpan<byte> line, ref string summary, ref bool chunked, ref long contentLength)
        {
            if (line.Length > MaxLine || line.Contains((byte)0)) return false;
            string text = Encoding.Latin1.GetString(line);
            int colon = text.IndexOf(':');
            if (colon <= 0 || !IsToken(text[..colon])) return false;
            string value = text[(colon + 1)..].Trim();
            if (value.Any(c => (c < ' ' && c != '\t') || c == '\u007f')) return false;
            if (text[..colon].Equals("Host", StringComparison.OrdinalIgnoreCase) && !summary.Contains(" · Host: "))
                summary = $"{summary} · Host: {value}";
            else if (text[..colon].Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long length) || length < 0) return false;
                if (contentLength >= 0 && contentLength != length) return false;
                contentLength = length;
            }
            else if (text[..colon].Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) &&
                value.Contains("chunked", StringComparison.OrdinalIgnoreCase))
            {
                chunked = true;
                contentLength = -1;
            }
            return true;
        }

        private static bool TryChunkSize(ReadOnlySpan<byte> line, out long size)
        {
            size = 0;
            int end = line.IndexOf((byte)';');
            ReadOnlySpan<byte> hex = end < 0 ? line : line[..end];
            if (hex.Length == 0 || hex.Length > 6) return false;
            foreach (byte digit in hex)
            {
                int value = digit switch { >= (byte)'0' and <= (byte)'9' => digit - '0', >= (byte)'a' and <= (byte)'f' => digit - 'a' + 10, >= (byte)'A' and <= (byte)'F' => digit - 'A' + 10, _ => -1 };
                if (value < 0) return false;
                size = (size << 4) + value;
            }
            return size <= Limit;
        }

        private static bool IsVersion(string value) => value is "HTTP/1.0" or "HTTP/1.1";
        private static bool IsToken(string value) => value.Length > 0 &&
            value.All(c => char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_|~".Contains(c));
        private static bool Printable(ReadOnlySpan<byte> data)
        {
            foreach (byte value in data)
                if (value is < 32 or >= 127) return false;
            return true;
        }
    }

    /// <summary>Recognizes a TLS stream from its hello and labels the subsequent records.</summary>
    private sealed class TlsStream
    {
        private bool _done;
        private int _offset;
        public List<StreamMessage> Scan(ReadOnlySpan<byte> data)
        {
            var found = new List<StreamMessage>();
            while (!_done && data.Length - _offset >= 5)
            {
                var header = data[_offset..];
                byte type = header[0];
                int length = (header[3] << 8) | header[4];
                if (type is < 20 or > 24 || header[1] != 3 || header[2] > 3 || length > 18_432 ||
                    _offset == 0 && type != 22)
                {
                    _done = true;
                    break;
                }
                if (length > header.Length - 5) break;
                string? summary = _offset == 0 ? Describe(header.Slice(5, length)) : type switch
                {
                    20 => "ChangeCipherSpec", 21 => "Alert", 22 => "握手记录", 23 => "加密记录", _ => "Heartbeat"
                };
                if (summary is null) { _done = true; break; }
                int next = _offset + 5 + length;
                found.Add(new StreamMessage("TLS", summary, "TLS 记录", "内容", _offset, next));
                _offset = next;
            }
            return found;
        }

        private static string? Describe(ReadOnlySpan<byte> record)
        {
            if (record.Length < 4) return null;
            int type = record[0];
            int length = (record[1] << 16) | (record[2] << 8) | record[3];
            if (type is not (1 or 2) || length < 34 || length > record.Length - 4) return null;
            ReadOnlySpan<byte> body = record.Slice(4, length);
            if (body[0] != 3 || body[1] is < 1 or > 3) return null;
            bool client = type == 1;
            if (!ReadHello(body, client, out byte version, out string? name)) return null;
            string summary = $"{(client ? "ClientHello" : "ServerHello")} · TLS 1.{version - 1}";
            return name is null ? summary : $"{summary} · SNI: {name}";
        }

        private static bool ReadHello(ReadOnlySpan<byte> body, bool client, out byte version, out string? name)
        {
            name = null;
            version = body[1];
            int cursor = 34;
            if (!Skip(body, ref cursor, 1)) return false;
            if (client)
            {
                if (!Skip(body, ref cursor, 2) || !Skip(body, ref cursor, 1)) return false;
            }
            else
            {
                if (body.Length - cursor < 3) return false;
                cursor += 3;
            }
            if (cursor == body.Length) return true;
            if (cursor + 2 > body.Length) return false;
            int extensionsLength = (body[cursor] << 8) | body[cursor + 1];
            cursor += 2;
            if (extensionsLength != body.Length - cursor) return false;
            int end = cursor + extensionsLength;
            while (cursor + 4 <= end)
            {
                int extensionType = (body[cursor] << 8) | body[cursor + 1];
                int extensionLength = (body[cursor + 2] << 8) | body[cursor + 3];
                cursor += 4;
                if (extensionLength > end - cursor) return false;
                ReadOnlySpan<byte> extension = body.Slice(cursor, extensionLength);
                if (client && extensionType == 0) name = HostName(extension);
                if (extensionType == 43)
                {
                    if (client && extension.Length >= 3 && extension[0] == extension.Length - 1 && extension[0] % 2 == 0)
                    {
                        for (int i = 1; i + 1 < extension.Length; i += 2)
                            if (extension[i] == 3 && extension[i + 1] is >= 1 and <= 4)
                                version = Math.Max(version, extension[i + 1]);
                    }
                    else if (!client && extension.Length == 2 && extension[0] == 3 && extension[1] is >= 1 and <= 4)
                        version = extension[1];
                }
                cursor += extensionLength;
            }
            return cursor == end;
        }

        private static string? HostName(ReadOnlySpan<byte> extension)
        {
            if (extension.Length < 5) return null;
            int listLength = (extension[0] << 8) | extension[1];
            if (listLength > extension.Length - 2 || extension[2] != 0) return null;
            int nameLength = (extension[3] << 8) | extension[4];
            if (nameLength is 0 or > 253 || nameLength > extension.Length - 5) return null;
            ReadOnlySpan<byte> name = extension.Slice(5, nameLength);
            foreach (byte value in name)
                if (value is < 33 or >= 127) return null;
            return Encoding.ASCII.GetString(name);
        }

        private static bool Skip(ReadOnlySpan<byte> body, ref int cursor, int lengthBytes)
        {
            if (cursor + lengthBytes > body.Length) return false;
            int length = lengthBytes == 1 ? body[cursor] : (body[cursor] << 8) | body[cursor + 1];
            cursor += lengthBytes;
            if (length > body.Length - cursor) return false;
            cursor += length;
            return true;
        }
    }
}

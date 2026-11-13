using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sniffer.Core;

public sealed record TlsStreamData(byte[] Forward, byte[] Reverse, string ForwardStatus, string ReverseStatus);
public sealed record TlsRecordRow(string Direction, int Offset, int Length, string Content);
public sealed record TlsInspection(string Status, IReadOnlyList<TlsRecordRow> Records, string ForwardText, string ReverseText);

public static class TlsInspector
{
    private const int HeaderSize = 5;
    private const int TagSize = 16;
    private static readonly byte[] RetryRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    public static TlsInspection Inspect(TlsStreamData stream, TextReader? keyLog = null)
    {
        byte[]? client = FindHello(stream.Forward, 1);
        bool clientForward = client is not null;
        client ??= FindHello(stream.Reverse, 1);
        byte[]? server = FindHello(clientForward ? stream.Reverse : stream.Forward, 2)
            ?? FindHello(clientForward ? stream.Forward : stream.Reverse, 2);
        if (client is null && server is null)
            return new("未识别到 TLS ClientHello 或 ServerHello。", [], "", "");

        int cipher = Cipher(server);
        bool tls13 = cipher is 0x1301 or 0x1302 or 0x1303 or 0x1304 or 0x1305;
        string version = tls13 ? "TLS 1.3" : server is null ? "TLS 版本未确认" : $"TLS 1.{server[1] - 1}";
        var records = new List<TlsRecordRow>();
        using var keys = KeyLog.Read(keyLog, client);
        using var forward = new Direction("A → B", clientForward ? "CLIENT" : "SERVER", tls13, cipher, keys, records);
        using var reverse = new Direction("B → A", clientForward ? "SERVER" : "CLIENT", tls13, cipher, keys, records);
        forward.Read(stream.Forward);
        reverse.Read(stream.Reverse);
        var status = new List<string> { version };
        if (cipher >= 0) status.Add($"套件 0x{cipher:X4}");
        if (keyLog is not null)
        {
            int decrypted = forward.Decrypted + reverse.Decrypted;
            status.Add(!tls13 || cipher is 0x1304 or 0x1305 ? "此会话的套件不在密钥日志解密范围内" :
                keys.Count == 0 ? "密钥日志中没有此 ClientHello 对应的 TLS 1.3 密钥" :
                $"已验证并解密 {decrypted} 条记录 · 认证失败 {forward.AuthenticationFailures + reverse.AuthenticationFailures}");
        }
        if (stream.ForwardStatus.Length > 0) status.Add($"A → B {stream.ForwardStatus}");
        if (stream.ReverseStatus.Length > 0) status.Add($"B → A {stream.ReverseStatus}");
        return new(string.Join(" · ", status), records, forward.Text, reverse.Text);
    }

    private static byte[]? FindHello(byte[] stream, int expected)
    {
        var handshake = new List<byte>();
        foreach (Record record in ReadRecords(stream))
        {
            if (record.Type == 20) continue;
            if (record.Type != 22 || record.Incomplete) break;
            handshake.AddRange(stream.AsSpan(record.Offset + HeaderSize, record.Length));
            int used = 0;
            while (handshake.Count - used >= 4)
            {
                int length = (handshake[used + 1] << 16) | (handshake[used + 2] << 8) | handshake[used + 3];
                if (length > handshake.Count - used - 4) break;
                if (handshake[used] == expected && length >= 35 && handshake[used + 4] == 3 &&
                    handshake[used + 5] is >= 1 and <= 3)
                {
                    byte[] hello = handshake.GetRange(used + 4, length).ToArray();
                    if (expected != 2 || !hello.AsSpan(2, 32).SequenceEqual(RetryRandom))
                        return hello;
                }
                used += 4 + length;
            }
            handshake.RemoveRange(0, used);
        }
        return null;
    }

    private static int Cipher(byte[]? server)
    {
        if (server is null || server.Length < 38) return -1;
        int index = 35 + server[34];
        return index <= server.Length - 3 ? BinaryPrimitives.ReadUInt16BigEndian(server.AsSpan(index)) : -1;
    }

    private static IEnumerable<Record> ReadRecords(byte[] stream)
    {
        for (int offset = 0; offset <= stream.Length - HeaderSize;)
        {
            byte type = stream[offset];
            int length = BinaryPrimitives.ReadUInt16BigEndian(stream.AsSpan(offset + 3));
            if (type is < 20 or > 24 || stream[offset + 1] != 3 || stream[offset + 2] > 3 || length > 18_432)
                yield break;
            bool truncated = length > stream.Length - offset - HeaderSize;
            yield return new Record(offset, type, length, truncated);
            if (truncated) yield break;
            offset += HeaderSize + length;
        }
    }

    private static ReadOnlySpan<byte> TakeVector(ReadOnlySpan<byte> data, ref int offset, int width)
    {
        if (data.Length - offset < width) throw new InvalidDataException();
        int length = 0;
        for (int i = 0; i < width; i++) length = (length << 8) | data[offset++];
        if (length > data.Length - offset) throw new InvalidDataException();
        ReadOnlySpan<byte> value = data.Slice(offset, length);
        offset += length;
        return value;
    }

    private static string CertificateDetails(ReadOnlySpan<byte> body, bool tls13)
    {
        try
        {
            int cursor = 0;
            if (tls13) TakeVector(body, ref cursor, 1);
            ReadOnlySpan<byte> chain = TakeVector(body, ref cursor, 3);
            var details = new List<string>();
            for (int position = 0; position < chain.Length;)
            {
                ReadOnlySpan<byte> der = TakeVector(chain, ref position, 3);
                using var certificate = X509CertificateLoader.LoadCertificate(der);
                string dns = certificate.GetNameInfo(X509NameType.DnsName, false);
                details.Add($"主体 {certificate.Subject} · 签发者 {certificate.Issuer} · DNS {dns} · " +
                    $"有效期 {certificate.NotBefore:yyyy-MM-dd} 至 {certificate.NotAfter:yyyy-MM-dd} · " +
                    $"SHA-256 {certificate.GetCertHashString(HashAlgorithmName.SHA256)}");
                if (tls13) TakeVector(chain, ref position, 2);
            }
            return details.Count == 0 ? "空证书链" : string.Join(" | ", details);
        }
        catch (Exception error) when (error is InvalidDataException or CryptographicException or ArgumentException)
        {
            return "证书链无法完整解析";
        }
    }

    private sealed record Record(int Offset, byte Type, int Length, bool Incomplete);

    private sealed class Direction(string name, string party, bool tls13, int cipher, KeyLog keys,
        List<TlsRecordRow> records) : IDisposable
    {
        private readonly List<byte> _handshake = [];
        private readonly List<byte> _plaintext = [];
        private TrafficKey? _active;
        private bool _finished;
        private bool _legacyEncrypted;
        public int Decrypted { get; private set; }
        public int AuthenticationFailures { get; private set; }
        public string Text => string.Join(" ", _plaintext.Select(value => value.ToString("X2"))) + (_plaintext.Count == 0 ? "" :
            "\n\nUTF-8\n" + SafeText(_plaintext.ToArray()));

        private static string SafeText(byte[] data) => string.Concat(Encoding.UTF8.GetString(data)
            .Select(ch => char.IsControl(ch) && ch is not ('\n' or '\r' or '\t') ? '·' : ch));

        public void Read(byte[] stream)
        {
            bool readCiphertext = false;
            foreach (Record record in ReadRecords(stream))
            {
                if (record.Incomplete) { Add(record, "记录未完整捕获"); return; }
                var header = stream.AsSpan(record.Offset, HeaderSize);
                var body = stream.AsSpan(record.Offset + HeaderSize, record.Length);
                if (record.Type == 23 && tls13)
                {
                    if (!readCiphertext)
                    {
                        ReplaceKey(keys.Find(party + "_HANDSHAKE_TRAFFIC_SECRET"));
                        readCiphertext = true;
                    }
                    ReadEncrypted(record, header, body);
                    continue;
                }
                switch (record.Type)
                {
                    case 20:
                        Add(record, "ChangeCipherSpec");
                        _legacyEncrypted = !tls13;
                        break;
                    case 21: Add(record, _legacyEncrypted ? "加密 Alert" : Alert(body)); break;
                    case 22: Add(record, _legacyEncrypted ? "加密握手" : Handshake(body)); break;
                    case 23: Add(record, "加密应用数据"); break;
                    case 24: Add(record, "Heartbeat"); break;
                }
            }
        }

        private void ReadEncrypted(Record record, ReadOnlySpan<byte> header, ReadOnlySpan<byte> body)
        {
            if (_active is null || body.Length <= TagSize)
            {
                Add(record, "加密记录");
                return;
            }
            byte[] plaintext = new byte[body.Length - TagSize];
            try
            {
                if (!_active.Open(header, body, plaintext))
                {
                    AuthenticationFailures++;
                    Add(record, "加密记录（认证失败）");
                    return;
                }
                Decrypted++;
                int type = plaintext.Length - 1;
                while (type >= 0 && plaintext[type] == 0) type--;
                switch (type >= 0 ? plaintext[type] : 0)
                {
                    case 21: Add(record, "已解密 · " + Alert(plaintext.AsSpan(0, type))); break;
                    case 22: Add(record, "已解密 · " + Handshake(plaintext.AsSpan(0, type))); break;
                    case 23:
                        Add(record, $"已解密 · 应用数据 {type} 字节 · {SafeText(plaintext.AsSpan(0, Math.Min(type, 48)).ToArray())}");
                        _plaintext.AddRange(plaintext.AsSpan(0, type));
                        break;
                    default: Add(record, "已解密 · 未知内部类型"); break;
                }
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }

        private string Handshake(ReadOnlySpan<byte> bytes)
        {
            _handshake.AddRange(bytes);
            var messages = new List<string>();
            int consumed = 0;
            while (_handshake.Count - consumed >= 4)
            {
                int type = _handshake[consumed];
                int length = (_handshake[consumed + 1] << 16) | (_handshake[consumed + 2] << 8) | _handshake[consumed + 3];
                if (length > _handshake.Count - consumed - 4) break;
                string message = type switch
                {
                    1 => "ClientHello", 2 => "ServerHello", 4 => "NewSessionTicket",
                    8 => "EncryptedExtensions", 11 => "Certificate · " + CertificateDetails(
                        System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_handshake).Slice(consumed + 4, length), tls13),
                    12 => "ServerKeyExchange", 13 => "CertificateRequest", 14 => "ServerHelloDone",
                    15 => "CertificateVerify", 16 => "ClientKeyExchange", 20 => "Finished", 24 => "KeyUpdate",
                    _ => $"握手类型 {type}"
                };
                if (tls13 && type == 20 && !_finished)
                {
                    _finished = true;
                    ReplaceKey(keys.Find(party + "_TRAFFIC_SECRET_0"));
                }
                else if (tls13 && type == 24 && _finished && _active is { } previous)
                {
                    _active = previous.Next();
                    previous.Dispose();
                }
                messages.Add(message);
                consumed += 4 + length;
            }
            _handshake.RemoveRange(0, consumed);
            return messages.Count == 0 ? "握手片段" : string.Join(" | ", messages);
        }

        private void ReplaceKey(byte[]? secret)
        {
            _active?.Dispose();
            _active = secret is not null && cipher is 0x1301 or 0x1302 or 0x1303 &&
                secret.Length == (cipher == 0x1302 ? 48 : 32) ? new TrafficKey(cipher, secret.ToArray()) : null;
        }

        private void Add(Record record, string text) => records.Add(new TlsRecordRow(name, record.Offset, record.Length, text));
        private static string Alert(ReadOnlySpan<byte> body) => body.Length < 2 ? "Alert" : $"Alert {body[0]}/{body[1]}";
        public void Dispose()
        {
            _active?.Dispose();
            System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_handshake).Clear();
            System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_plaintext).Clear();
        }
    }

    private sealed class TrafficKey(int cipher, byte[] secret) : IDisposable
    {
        private readonly byte[] _key = Expand(cipher, secret, "key", cipher == 0x1301 ? 16 : 32);
        private readonly byte[] _iv = Expand(cipher, secret, "iv", 12);
        private ulong _sequence;

        public bool Open(ReadOnlySpan<byte> header, ReadOnlySpan<byte> body, Span<byte> output)
        {
            Span<byte> nonce = stackalloc byte[12];
            _iv.CopyTo(nonce);
            ulong number = BinaryPrimitives.ReadUInt64BigEndian(nonce[4..]) ^ _sequence++;
            BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], number);
            try
            {
                if (cipher == 0x1303)
                {
                    using var aead = new ChaCha20Poly1305(_key);
                    aead.Decrypt(nonce, body[..^TagSize], body[^TagSize..], output, header);
                }
                else
                {
                    using var aead = new AesGcm(_key, TagSize);
                    aead.Decrypt(nonce, body[..^TagSize], body[^TagSize..], output, header);
                }
                return true;
            }
            catch (AuthenticationTagMismatchException) { return false; }
        }

        private static byte[] Expand(int cipher, byte[] secret, string label, int count)
        {
            byte[] name = Encoding.ASCII.GetBytes("tls13 " + label);
            var info = new byte[4 + name.Length];
            BinaryPrimitives.WriteUInt16BigEndian(info, (ushort)count);
            info[2] = (byte)name.Length;
            name.CopyTo(info, 3);
            return HKDF.Expand(cipher == 0x1302 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256, secret, count, info);
        }

        public TrafficKey Next() => new(cipher, Expand(cipher, secret, "traffic upd", secret.Length));

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_key);
            CryptographicOperations.ZeroMemory(_iv);
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private sealed class KeyLog : IDisposable
    {
        private readonly Dictionary<string, byte[]> _secrets = new(StringComparer.Ordinal);
        public int Count => _secrets.Count;
        public byte[]? Find(string label) => _secrets.GetValueOrDefault(label);

        public static KeyLog Read(TextReader? reader, byte[]? client)
        {
            var keys = new KeyLog();
            if (reader is null || client is null) return keys;
            string random = Convert.ToHexString(client.AsSpan(2, 32));
            try
            {
                while (reader.ReadLine() is { } line)
                {
                    if (line.Length > 512) continue;
                    string[] parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length != 3 || !random.Equals(parts[1], StringComparison.OrdinalIgnoreCase) ||
                        parts[0] is not ("CLIENT_HANDSHAKE_TRAFFIC_SECRET" or "SERVER_HANDSHAKE_TRAFFIC_SECRET" or
                            "CLIENT_TRAFFIC_SECRET_0" or "SERVER_TRAFFIC_SECRET_0") || parts[2].Length is not (64 or 96) ||
                        keys._secrets.ContainsKey(parts[0])) continue;
                    try { keys._secrets.Add(parts[0], Convert.FromHexString(parts[2])); }
                    catch (FormatException) { }
                }
                return keys;
            }
            catch { keys.Dispose(); throw; }
        }

        public void Dispose()
        {
            foreach (byte[] secret in _secrets.Values) CryptographicOperations.ZeroMemory(secret);
            _secrets.Clear();
        }
    }
}

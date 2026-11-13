using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;

namespace Sniffer.Desktop;

internal sealed class CountryLookup
{
    private readonly List<Range> _v4 = [];
    private readonly List<Range> _v6 = [];

    public CountryLookup()
    {
        using var file = typeof(CountryLookup).Assembly.GetManifestResourceStream("Sniffer.CountryData")
            ?? throw new InvalidDataException("找不到国家和地区数据库。");
        using var reader = new StreamReader(new GZipStream(file, CompressionMode.Decompress));
        while (reader.ReadLine() is { } line)
        {
            ReadOnlySpan<char> row = line.AsSpan();
            int first = row.IndexOf(',');
            int last = row.LastIndexOf(',');
            if (first < 1 || last <= first || row.Length - last != 3 ||
                !IPAddress.TryParse(row[..first], out IPAddress? start) ||
                !IPAddress.TryParse(row[(first + 1)..last], out IPAddress? end)) continue;
            var ranges = start.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? _v4 : _v6;
            ranges.Add(new Range(Number(start), Number(end), row[(last + 1)..].ToString()));
        }
        _v4.Sort((a, b) => a.First.CompareTo(b.First));
        _v6.Sort((a, b) => a.First.CompareTo(b.First));
    }

    public string Find(IPAddress ip)
    {
        UInt128 number = Number(ip);
        byte[] bytes = ip.GetAddressBytes();
        bool ipv4 = bytes.Length == 4;
        if (IPAddress.IsLoopback(ip) || (ipv4 ? bytes[0] is 0 or 10 or >= 224 ||
            bytes[0] == 169 && bytes[1] == 254 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
            bytes[0] == 192 && (bytes[1] == 168 || bytes[1] == 0 && bytes[2] == 2) ||
            bytes[0] == 198 && (bytes[1] is 18 or 19 || bytes[1] == 51 && bytes[2] == 100) ||
            bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113 || bytes[0] == 100 && bytes[1] is >= 64 and <= 127
            : ip.Equals(IPAddress.IPv6Any) || ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || (bytes[0] & 0xfe) == 0xfc ||
                BinaryPrimitives.ReadUInt32BigEndian(bytes) == 0x20010DB8))
            return "本地 / 保留";
        List<Range> ranges = ipv4 ? _v4 : _v6;
        int low = 0, high = ranges.Count - 1;
        while (low <= high)
        {
            int mid = low + (high - low) / 2;
            Range range = ranges[mid];
            if (number < range.First) high = mid - 1;
            else if (number > range.Last) low = mid + 1;
            else if (range.Code == "ZZ") break;
            else
            {
                try
                {
                    string name = new RegionInfo(range.Code).DisplayName;
                    string flag = string.Concat(range.Code.Select(letter => char.ConvertFromUtf32(0x1F1E6 + letter - 'A')));
                    return $"{flag} {range.Code} · {name}";
                }
                catch (ArgumentException) { return range.Code; }
            }
        }
        return "—";
    }

    private static UInt128 Number(IPAddress ip)
    {
        Span<byte> bytes = stackalloc byte[16];
        ip.TryWriteBytes(bytes, out int count);
        return count == 4 ? BinaryPrimitives.ReadUInt32BigEndian(bytes) : BinaryPrimitives.ReadUInt128BigEndian(bytes);
    }

    private readonly record struct Range(UInt128 First, UInt128 Last, string Code);
}

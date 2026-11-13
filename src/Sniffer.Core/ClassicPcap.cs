using System.Buffers.Binary;

namespace Sniffer.Core;

public static class ClassicPcap
{
    public const int MaxFrame = 262_144;

    public static IEnumerable<RawPacket> Read(Stream stream)
    {
        var header = new byte[24];
        ReadExactly(stream, header, "PCAP 文件头不完整。");
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(header);
        bool littleEndian = magic is 0xa1b2c3d4 or 0xa1b23c4d;
        bool nanoseconds = magic is 0xa1b23c4d or 0x4d3cb2a1;
        if (magic is not (0xa1b2c3d4 or 0xd4c3b2a1 or 0xa1b23c4d or 0x4d3cb2a1))
            throw new InvalidDataException("仅支持经典 PCAP（.pcap），请先将 PCAPNG 转为 PCAP。");

        uint Read32(ReadOnlySpan<byte> bytes) => littleEndian
            ? BinaryPrimitives.ReadUInt32LittleEndian(bytes) : BinaryPrimitives.ReadUInt32BigEndian(bytes);
        ushort Read16(ReadOnlySpan<byte> bytes) => littleEndian
            ? BinaryPrimitives.ReadUInt16LittleEndian(bytes) : BinaryPrimitives.ReadUInt16BigEndian(bytes);

        if (Read16(header.AsSpan(4)) != 2 || Read16(header.AsSpan(6)) != 4)
            throw new InvalidDataException("不支持的 PCAP 文件版本。");
        uint snaplen = Read32(header.AsSpan(16));
        var link = (LinkType)(Read32(header.AsSpan(20)) & 0xffff);
        ValidateLink(link);
        if (snaplen == 0)
            throw new InvalidDataException("PCAP 快照长度为 0。");

        var record = new byte[16];
        while (true)
        {
            int first = stream.ReadByte();
            if (first < 0)
                yield break;
            record[0] = (byte)first;
            ReadExactly(stream, record.AsSpan(1), "PCAP 包记录头不完整。");
            uint seconds = Read32(record);
            uint fraction = Read32(record.AsSpan(4));
            uint captured = Read32(record.AsSpan(8));
            uint original = Read32(record.AsSpan(12));
            if (fraction >= (nanoseconds ? 1_000_000_000u : 1_000_000u) ||
                captured > snaplen || captured > MaxFrame || captured > original)
                throw new InvalidDataException("PCAP 包记录的长度或时间戳无效。");

            var bytes = new byte[captured];
            ReadExactly(stream, bytes, "PCAP 包数据被截断。");
            long ticks = nanoseconds ? fraction / 100 : (long)fraction * 10;
            yield return new RawPacket(DateTimeOffset.FromUnixTimeSeconds(seconds).AddTicks(ticks), link, original, bytes);
        }
    }

    public static void ValidateLink(LinkType link)
    {
        if (link is not (LinkType.Ethernet or LinkType.Null or LinkType.RawIp))
            throw new NotSupportedException($"暂不支持链路类型 {(uint)link}。支持 Ethernet、Loopback 和原始 IP。");
    }

    private static void ReadExactly(Stream stream, Span<byte> buffer, string message)
    {
        try { stream.ReadExactly(buffer); }
        catch (EndOfStreamException exception) { throw new InvalidDataException(message, exception); }
    }
}

public sealed class PcapWriter
{
    private readonly Stream _stream;
    private readonly LinkType _link;

    public PcapWriter(Stream stream, LinkType link)
    {
        ClassicPcap.ValidateLink(link);
        _stream = stream;
        _link = link;
        Span<byte> header = stackalloc byte[24];
        header.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0xa1b2c3d4);
        BinaryPrimitives.WriteUInt16LittleEndian(header[4..], 2);
        BinaryPrimitives.WriteUInt16LittleEndian(header[6..], 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header[16..], ClassicPcap.MaxFrame);
        BinaryPrimitives.WriteUInt32LittleEndian(header[20..], (uint)link);
        _stream.Write(header);
    }

    public void Write(RawPacket packet)
    {
        if (packet.Link != _link || packet.Bytes.Length > ClassicPcap.MaxFrame ||
            packet.Bytes.Length > packet.WireLength)
            throw new InvalidDataException("包链路类型或长度与导出配置不符。");

        Span<byte> header = stackalloc byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(header, checked((uint)packet.Timestamp.ToUnixTimeSeconds()));
        BinaryPrimitives.WriteUInt32LittleEndian(header[4..], (uint)(packet.Timestamp.UtcTicks % TimeSpan.TicksPerSecond / 10));
        BinaryPrimitives.WriteUInt32LittleEndian(header[8..], (uint)packet.Bytes.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(header[12..], packet.WireLength);
        _stream.Write(header);
        _stream.Write(packet.Bytes);
    }
}

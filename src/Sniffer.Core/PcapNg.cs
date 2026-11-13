using System.Buffers.Binary;

namespace Sniffer.Core;

public static class CaptureFile
{
    public static IEnumerable<RawPacket> Read(Stream stream)
    {
        var magic = new byte[4];
        ReadExactly(stream, magic, "抓包文件头不完整。");
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(magic);
        var prefixed = new PrefixedStream(stream, magic);
        return value switch
        {
            0x0a0d0d0a => PcapNg.Read(prefixed),
            0xa1b2c3d4 or 0xd4c3b2a1 or 0xa1b23c4d or 0x4d3cb2a1 => ClassicPcap.Read(prefixed),
            _ => throw new InvalidDataException("不是 PCAP 或 PCAPNG 文件。")
        };
    }

    internal static void ReadExactly(Stream stream, Span<byte> buffer, string message)
    {
        try { stream.ReadExactly(buffer); }
        catch (EndOfStreamException exception) { throw new InvalidDataException(message, exception); }
    }

    private sealed class PrefixedStream(Stream inner, byte[] prefix) : Stream
    {
        private int _consumed;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(Span<byte> buffer)
        {
            if (_consumed == prefix.Length) return inner.Read(buffer);
            int count = Math.Min(buffer.Length, prefix.Length - _consumed);
            prefix.AsSpan(_consumed, count).CopyTo(buffer);
            _consumed += count;
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int ReadByte() => _consumed == prefix.Length ? inner.ReadByte() : prefix[_consumed++];
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

public static class PcapNg
{
    private const uint Section = 0x0a0d0d0a;
    private const uint ByteOrder = 0x1a2b3c4d;
    private const uint InterfaceBlock = 1;
    private const uint SimplePacket = 3;
    private const uint EnhancedPacket = 6;
    private const int MaxBlockLength = 16 * 1024 * 1024;

    public static IEnumerable<RawPacket> Read(Stream stream)
    {
        var header = new byte[8];
        var marker = new byte[4];
        var interfaces = new List<CaptureInterface>();
        bool sectionSeen = false;
        bool little = true;
        while (true)
        {
            int first = stream.ReadByte();
            if (first < 0) yield break;
            header[0] = (byte)first;
            CaptureFile.ReadExactly(stream, header.AsSpan(1), "PCAPNG 块头不完整。");

            bool newSection = BinaryPrimitives.ReadUInt32LittleEndian(header) == Section;
            if (newSection)
            {
                CaptureFile.ReadExactly(stream, marker, "PCAPNG 节头不完整。");
                little = BinaryPrimitives.ReadUInt32LittleEndian(marker) switch
                {
                    ByteOrder => true,
                    0x4d3c2b1a => false,
                    _ => throw new InvalidDataException("PCAPNG 字节序标记无效。")
                };
            }
            else if (!sectionSeen)
            {
                throw new InvalidDataException("PCAPNG 缺少节头。");
            }

            uint type = U32(header, little);
            uint total = U32(header.AsSpan(4), little);
            if (total < (newSection ? 28u : 12u) || total % 4 != 0 || total > MaxBlockLength)
                throw new InvalidDataException("PCAPNG 块长度无效。");
            var body = new byte[total - 8];
            int alreadyRead = newSection ? marker.Length : 0;
            if (newSection) marker.CopyTo(body, 0);
            CaptureFile.ReadExactly(stream, body.AsSpan(alreadyRead), "PCAPNG 块被截断。");
            if (U32(body.AsSpan(body.Length - 4), little) != total)
                throw new InvalidDataException("PCAPNG 块尾长度不一致。");
            ReadOnlySpan<byte> data = body.AsSpan(0, body.Length - 4);
            switch (type)
            {
                case Section:
                    if (U16(data[4..], little) != 1)
                        throw new InvalidDataException("不支持的 PCAPNG 节版本。");
                    sectionSeen = true;
                    interfaces.Clear();
                    break;
                case InterfaceBlock:
                    if (interfaces.Count >= 4096) throw new InvalidDataException("PCAPNG 接口数量超出支持范围。");
                    interfaces.Add(ReadInterface(data, little));
                    break;
                case EnhancedPacket:
                    if (data.Length < 20) throw new InvalidDataException("PCAPNG 报文块不完整。");
                    uint id = U32(data, little);
                    if (id >= interfaces.Count) throw new InvalidDataException("PCAPNG 报文引用了不存在的接口。");
                    CaptureInterface iface = interfaces[(int)id];
                    ulong ticks = ((ulong)U32(data[4..], little) << 32) | U32(data[8..], little);
                    yield return ReadPacket(iface, Timestamp(ticks, iface), U32(data[12..], little),
                        U32(data[16..], little), data[20..]);
                    break;
                case SimplePacket:
                    if (interfaces.Count == 0 || data.Length < 4)
                        throw new InvalidDataException("PCAPNG 简单报文块缺少接口或长度。");
                    uint original = U32(data, little);
                    uint captured = Math.Min(original, interfaces[0].Snaplen);
                    if (captured > ClassicPcap.MaxFrame || data.Length - 4 != Aligned((int)captured))
                        throw new InvalidDataException("PCAPNG 简单报文块长度无效。");
                    yield return ReadPacket(interfaces[0], DateTimeOffset.UnixEpoch, captured, original, data[4..]);
                    break;
            }
        }
    }

    public static void Write(Stream stream, IReadOnlyList<RawPacket> packets)
    {
        var interfaceIds = new Dictionary<LinkType, uint>();
        long epoch = 0;
        foreach (RawPacket packet in packets)
        {
            ClassicPcap.ValidateLink(packet.Link);
            if (packet.Bytes.Length > ClassicPcap.MaxFrame || packet.Bytes.Length > packet.WireLength)
                throw new InvalidDataException("PCAPNG 报文长度无效。");
            interfaceIds.TryAdd(packet.Link, (uint)interfaceIds.Count);
            epoch = Math.Min(epoch, packet.Timestamp.ToUnixTimeSeconds());
        }

        Span<byte> section = stackalloc byte[16];
        section.Clear();
        Put32(section, ByteOrder);
        BinaryPrimitives.WriteUInt16LittleEndian(section[4..], 1);
        BinaryPrimitives.WriteInt64LittleEndian(section[8..], -1);
        WriteBlock(stream, Section, section);

        Span<byte> iface = stackalloc byte[32];
        foreach (LinkType link in interfaceIds.Keys)
        {
            iface.Clear();
            BinaryPrimitives.WriteUInt16LittleEndian(iface, (ushort)link);
            Put32(iface[4..], ClassicPcap.MaxFrame);
            BinaryPrimitives.WriteUInt16LittleEndian(iface[8..], 9);
            BinaryPrimitives.WriteUInt16LittleEndian(iface[10..], 1);
            iface[12] = 7;
            BinaryPrimitives.WriteUInt16LittleEndian(iface[16..], 14);
            BinaryPrimitives.WriteUInt16LittleEndian(iface[18..], 8);
            BinaryPrimitives.WriteInt64LittleEndian(iface[20..], epoch);
            WriteBlock(stream, InterfaceBlock, iface);
        }

        long origin = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcTicks;
        Span<byte> fields = stackalloc byte[20];
        Span<byte> padding = stackalloc byte[3];
        padding.Clear();
        foreach (RawPacket packet in packets)
        {
            ulong ticks = (ulong)(packet.Timestamp.UtcTicks - origin);
            Put32(fields, interfaceIds[packet.Link]);
            Put32(fields[4..], (uint)(ticks >> 32));
            Put32(fields[8..], (uint)ticks);
            Put32(fields[12..], (uint)packet.Bytes.Length);
            Put32(fields[16..], packet.WireLength);
            WriteBlock(stream, EnhancedPacket, fields, packet.Bytes, padding[..(Aligned(packet.Bytes.Length) - packet.Bytes.Length)]);
        }
    }

    private static CaptureInterface ReadInterface(ReadOnlySpan<byte> data, bool little)
    {
        if (data.Length < 8) throw new InvalidDataException("PCAPNG 接口描述不完整。");
        var link = (LinkType)U16(data, little);
        uint snaplen = U32(data[4..], little);
        byte resolution = 6;
        long offset = 0;
        for (int cursor = 8; cursor < data.Length;)
        {
            if (data.Length - cursor < 4) throw new InvalidDataException("PCAPNG 选项头不完整。");
            ushort code = U16(data[cursor..], little);
            ushort length = U16(data[(cursor + 2)..], little);
            cursor += 4;
            if (code == 0)
            {
                if (length != 0 || cursor != data.Length) throw new InvalidDataException("PCAPNG 选项终止符无效。");
                break;
            }
            if (Aligned(length) > data.Length - cursor) throw new InvalidDataException("PCAPNG 选项被截断。");
            if (code == 9 && length == 1) resolution = data[cursor];
            if (code == 14 && length == 8)
                offset = little ? BinaryPrimitives.ReadInt64LittleEndian(data[cursor..])
                    : BinaryPrimitives.ReadInt64BigEndian(data[cursor..]);
            cursor += Aligned(length);
        }
        return new CaptureInterface(link, snaplen == 0 ? uint.MaxValue : snaplen, resolution, offset);
    }

    private static RawPacket ReadPacket(CaptureInterface iface, DateTimeOffset timestamp, uint captured, uint original,
        ReadOnlySpan<byte> data)
    {
        if (captured > iface.Snaplen || captured > ClassicPcap.MaxFrame || captured > original || Aligned((int)captured) > data.Length)
            throw new InvalidDataException("PCAPNG 报文长度无效。");
        ClassicPcap.ValidateLink(iface.Link);
        return new RawPacket(timestamp, iface.Link, original, data[..(int)captured].ToArray());
    }

    private static DateTimeOffset Timestamp(ulong units, CaptureInterface iface)
    {
        UInt128 scaled = (UInt128)units * TimeSpan.TicksPerSecond;
        int power = iface.Resolution & 0x7f;
        UInt128 ticks = 0;
        if ((iface.Resolution & 0x80) != 0)
            ticks = scaled >> power;
        else if (power <= 38)
        {
            UInt128 scale = 1;
            for (int i = 0; i < power; i++) scale *= 10;
            ticks = scaled / scale;
        }

        Int128 utcTicks = DateTimeOffset.UnixEpoch.UtcTicks + (Int128)iface.Offset * TimeSpan.TicksPerSecond + (Int128)ticks;
        if (utcTicks < 0 || utcTicks > DateTimeOffset.MaxValue.UtcTicks)
            throw new InvalidDataException("PCAPNG 时间戳超出范围。");
        return new DateTimeOffset((long)utcTicks, TimeSpan.Zero);
    }

    private static void WriteBlock(Stream stream, uint type, ReadOnlySpan<byte> fields, ReadOnlySpan<byte> data = default,
        ReadOnlySpan<byte> padding = default)
    {
        Span<byte> header = stackalloc byte[8];
        Put32(header, type);
        Put32(header[4..], (uint)(12 + fields.Length + data.Length + padding.Length));
        stream.Write(header);
        stream.Write(fields);
        stream.Write(data);
        stream.Write(padding);
        stream.Write(header[4..]);
    }

    private static int Aligned(int length) => (length + 3) & ~3;
    private static ushort U16(ReadOnlySpan<byte> value, bool little) => little
        ? BinaryPrimitives.ReadUInt16LittleEndian(value) : BinaryPrimitives.ReadUInt16BigEndian(value);
    private static uint U32(ReadOnlySpan<byte> value, bool little) => little
        ? BinaryPrimitives.ReadUInt32LittleEndian(value) : BinaryPrimitives.ReadUInt32BigEndian(value);
    private static void Put32(Span<byte> target, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(target, value);

    private readonly record struct CaptureInterface(LinkType Link, uint Snaplen, byte Resolution, long Offset);
}

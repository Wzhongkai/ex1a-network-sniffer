using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Sniffer.Core;

public static class DemoTrace
{
    public static IEnumerable<RawPacket> Read()
    {
        var origin = DateTimeOffset.UtcNow;
        int tick = 0;
        RawPacket Stamp(RawPacket raw) => raw with { Timestamp = origin.AddMilliseconds(tick++ * 17) };

        const ushort server = 8080;
        const ushort client = 49612;
        byte[] request = Encoding.ASCII.GetBytes("GET /lab/packets HTTP/1.1\r\nHost: lab.local:8080\r\nConnection: close\r\n\r\n");
        byte[] response = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nhello sniffer");
        yield return Stamp(Tcp(false, client, server, 1200, 0, 2, []));
        yield return Stamp(Tcp(false, server, client, 9500, 1201, 18, [], reverse: true));
        yield return Stamp(Tcp(false, client, server, 1201, 9501, 16, []));
        yield return Stamp(Tcp(false, client, server, 1201, 9501, 24, request[..9]));
        yield return Stamp(Tcp(false, client, server, 1226, 9501, 24, request[25..]));
        yield return Stamp(Tcp(false, client, server, 1210, 9501, 24, request[9..25]));
        yield return Stamp(Tcp(false, server, client, 9501, 1201 + (uint)request.Length, 24, response, reverse: true));
        yield return Stamp(Tcp(false, client, server, 1201, 9501, 24, request[..9]));
        yield return Stamp(Tcp(false, client, server, 1201 + (uint)request.Length, 9501 + (uint)response.Length, 17, []));
        yield return Stamp(Tcp(false, server, client, 9501 + (uint)response.Length, 1202 + (uint)request.Length, 17, [], reverse: true));
        yield return Stamp(Tcp(true, 49613, 8080, 6000, 0, 2, []));
        yield return Stamp(Tcp(true, 8080, 49613, 7220, 6001, 18, [], reverse: true));
        yield return Stamp(Tcp(true, 49613, 8080, 6001, 7221, 24, [0, 17, 34, 51, 68, 85], extension: true));
        yield return Stamp(Tcp(true, 8080, 49613, 7221, 6007, 20, [], reverse: true));
        yield return Stamp(Udp(false, 53001, 5353, "hello UDP"u8));
        yield return Stamp(Udp(true, 53002, 5353, "hello IPv6"u8));
        yield return Stamp(Echo(false));
        yield return Stamp(Echo(true));
        yield return Stamp(Udp(false, 53010, 53, DnsQuery()));
        yield return Stamp(Udp(false, 53, 53010, DnsAnswer(), reverse: true));
        yield return Stamp(Tcp(false, 49700, 443, 100, 0, 2, []));
        yield return Stamp(Tcp(false, 443, 49700, 900, 101, 18, [], reverse: true));
        yield return Stamp(Tcp(false, 49700, 443, 101, 901, 24, ClientHello()));
    }

    public static RawPacket Tcp(bool ipv6, ushort source, ushort destination, uint sequence,
        uint acknowledgment, byte flags, ReadOnlySpan<byte> data, bool reverse = false, bool extension = false)
    {
        byte[] payload = new byte[20 + data.Length];
        U16(payload, source);
        U16(payload.AsSpan(2), destination);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4), sequence);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(8), acknowledgment);
        payload[12] = 0x50;
        payload[13] = flags;
        U16(payload.AsSpan(14), 32768);
        data.CopyTo(payload.AsSpan(20));
        return Ip(ipv6, 6, payload, reverse, extension);
    }

    public static RawPacket Udp(bool ipv6, ushort source, ushort destination, ReadOnlySpan<byte> data, bool reverse = false)
    {
        byte[] payload = new byte[8 + data.Length];
        U16(payload, source);
        U16(payload.AsSpan(2), destination);
        U16(payload.AsSpan(4), (ushort)payload.Length);
        data.CopyTo(payload.AsSpan(8));
        return Ip(ipv6, 17, payload, reverse);
    }

    public static RawPacket Echo(bool ipv6)
    {
        byte[] payload = [ipv6 ? (byte)128 : (byte)8, 0, 0, 0, 0, 21, 0, 1, 65, 66, 67, 68];
        return Ip(ipv6, ipv6 ? (byte)58 : (byte)1, payload);
    }

    private static RawPacket Ip(bool ipv6, byte protocol, byte[] payload, bool reverse = false, bool extension = false)
    {
        byte[] source = IPAddress.Parse(ipv6 ? "2001:db8::1" : "192.0.2.10").GetAddressBytes();
        byte[] destination = IPAddress.Parse(ipv6 ? "2001:db8::2" : "192.0.2.20").GetAddressBytes();
        if (reverse) (source, destination) = (destination, source);
        int ipHeader = ipv6 ? 40 : 20;
        int extensionLength = ipv6 && extension ? 8 : 0;
        byte[] bytes = new byte[14 + ipHeader + extensionLength + payload.Length];
        byte[] macA = [2, 0, 0, 0, 0, 1];
        byte[] macB = [2, 0, 0, 0, 0, 2];
        (reverse ? macA : macB).CopyTo(bytes, 0);
        (reverse ? macB : macA).CopyTo(bytes, 6);
        U16(bytes.AsSpan(12), ipv6 ? (ushort)0x86dd : (ushort)0x0800);
        Span<byte> ip = bytes.AsSpan(14);
        if (ipv6)
        {
            ip[0] = 0x60;
            U16(ip[4..], (ushort)(payload.Length + extensionLength));
            ip[6] = extensionLength > 0 ? (byte)0 : protocol;
            ip[7] = 64;
            source.CopyTo(ip[8..]);
            destination.CopyTo(ip[24..]);
            if (extensionLength > 0) ip[40] = protocol;
        }
        else
        {
            ip[0] = 0x45;
            U16(ip[2..], (ushort)(ipHeader + payload.Length));
            ip[8] = 64;
            ip[9] = protocol;
            source.CopyTo(ip[12..]);
            destination.CopyTo(ip[16..]);
            U16(ip[10..], Checksum(ip[..20]));
        }

        int checksum = protocol switch { 6 => 16, 17 => 6, 1 or 58 => 2, _ => -1 };
        if (checksum >= 0)
        {
            byte[] pseudo = new byte[ipv6 ? 40 : 12];
            source.CopyTo(pseudo, 0);
            destination.CopyTo(pseudo, source.Length);
            U16(pseudo.AsSpan(ipv6 ? 34 : 10), (ushort)payload.Length);
            pseudo[ipv6 ? 39 : 9] = protocol;
            uint sum = protocol == 1 ? 0 : Sum(pseudo);
            ushort computed = Checksum(payload, sum);
            U16(payload.AsSpan(checksum), protocol == 17 && computed == 0 ? ushort.MaxValue : computed);
        }
        payload.CopyTo(ip[(ipHeader + extensionLength)..]);
        return new RawPacket(DateTimeOffset.UtcNow, LinkType.Ethernet, (uint)bytes.Length, bytes);
    }

    private static ushort Checksum(ReadOnlySpan<byte> bytes, uint initial = 0)
    {
        uint sum = initial + Sum(bytes);
        while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
        return (ushort)~sum;
    }

    private static uint Sum(ReadOnlySpan<byte> bytes)
    {
        uint sum = 0;
        int i = 0;
        for (; i + 1 < bytes.Length; i += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(bytes[i..]);
        if (i < bytes.Length) sum += (uint)(bytes[i] << 8);
        return sum;
    }

    private static byte[] DnsQuery()
    {
        var name = new List<byte>();
        foreach (string label in new[] { "lab", "example" })
        {
            name.Add((byte)label.Length);
            name.AddRange(Encoding.ASCII.GetBytes(label));
        }
        name.Add(0);
        var bytes = new byte[12 + name.Count + 4];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, 0x1a2b);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        name.CopyTo(bytes, 12);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12 + name.Count + 2), 1);
        return bytes;
    }

    private static byte[] DnsAnswer()
    {
        byte[] query = DnsQuery();
        var bytes = new byte[query.Length + 16];
        query.CopyTo(bytes, 0);
        bytes[2] = 0x81;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 1);
        bytes[query.Length] = 0xc0;
        bytes[query.Length + 1] = 12;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(query.Length + 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(query.Length + 4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(query.Length + 10), 4);
        IPAddress.Parse("192.0.2.20").GetAddressBytes().CopyTo(bytes, query.Length + 12);
        return bytes;
    }

    private static byte[] ClientHello()
    {
        byte[] name = "lab.example"u8.ToArray();
        int nameEntryLength = 1 + 2 + name.Length;
        int extensions = 4 + 2 + nameEntryLength;
        int handshake = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions;
        var bytes = new byte[5 + 4 + handshake];
        bytes[0] = 22;
        bytes[1] = 3;
        bytes[2] = 3;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(3), (ushort)(bytes.Length - 5));
        bytes[5] = 1;
        bytes[6] = (byte)(handshake >> 16);
        bytes[7] = (byte)(handshake >> 8);
        bytes[8] = (byte)handshake;
        bytes[9] = 3;
        bytes[10] = 3;
        int cursor = 43;
        bytes[cursor++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(cursor), 2);
        cursor += 2;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(cursor), 0x002f);
        cursor += 2;
        bytes[cursor++] = 1;
        bytes[cursor++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(cursor), (ushort)extensions);
        cursor += 2;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(cursor), 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(cursor + 2), (ushort)(2 + nameEntryLength));
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(cursor + 4), (ushort)nameEntryLength);
        bytes[cursor + 6] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(cursor + 7), (ushort)name.Length);
        name.CopyTo(bytes, cursor + 9);
        return bytes;
    }

    private static void U16(Span<byte> bytes, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
}

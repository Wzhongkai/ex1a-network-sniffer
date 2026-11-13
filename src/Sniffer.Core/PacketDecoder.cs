using System.Buffers.Binary;
using System.Net;

namespace Sniffer.Core;

public static class PacketDecoder
{
    public static Packet Decode(long number, RawPacket raw)
    {
        var packet = new Packet(number, raw);
        var decoder = new Decoder(packet);
        decoder.Decode();
        return packet;
    }

    private sealed class Decoder(Packet packet)
    {
        private byte[] Bytes => packet.Raw.Bytes;

        public void Decode()
        {
            if (Bytes.Length < packet.Raw.WireLength)
                packet.Note = "捕获截断";
            switch (packet.Raw.Link)
            {
                case LinkType.Ethernet: Ethernet(); break;
                case LinkType.Null: Loopback(); break;
                case LinkType.RawIp:
                    packet.LinkSummary = "Raw IP";
                    if (!Need(0, 1, Bytes.Length, "IP")) break;
                    if (Bytes[0] >> 4 == 4) Ipv4(0);
                    else if (Bytes[0] >> 4 == 6) Ipv6(0);
                    else Note("未知 IP 版本");
                    break;
                default: Note($"未知链路类型 {(uint)packet.Raw.Link}"); break;
            }
        }

        private void Ethernet()
        {
            packet.LinkSummary = "Ethernet";
            if (!Need(0, 14, Bytes.Length, "Ethernet")) return;
            ushort type = U16(12);
            string destination = Mac(0);
            string source = Mac(6);
            packet.TransportSummary = $"{source} → {destination}";
            Layer("Ethernet II", 0, 14, F("目标 MAC", destination, 0, 6),
                F("源 MAC", source, 6, 6), F("EtherType", $"0x{type:X4}", 12, 2));
            int offset = 14;
            while (type is 0x8100 or 0x88a8)
            {
                if (offset >= 30)
                {
                    Note("VLAN 嵌套超出解析上限");
                    return;
                }
                if (!Need(offset, 4, Bytes.Length, "VLAN")) return;
                ushort tci = U16(offset);
                type = U16(offset + 2);
                Layer("802.1Q VLAN", offset, 4, F("VLAN ID", tci & 4095, offset, 2),
                    F("优先级", tci >> 13, offset, 2), F("内层 EtherType", $"0x{type:X4}", offset + 2, 2));
                offset += 4;
            }

            switch (type)
            {
                case 0x0800: Ipv4(offset); break;
                case 0x86dd: Ipv6(offset); break;
                case 0x0806: Arp(offset); break;
            }
        }

        private void Loopback()
        {
            packet.LinkSummary = "Loopback";
            if (!Need(0, 4, Bytes.Length, "Loopback")) return;
            uint family = BinaryPrimitives.ReadUInt32LittleEndian(Bytes);
            if (family > 255)
                family = BinaryPrimitives.ReadUInt32BigEndian(Bytes);
            Layer("Loopback (DLT_NULL)", 0, 4, F("地址族", family, 0, 4));
            switch (family)
            {
                case 2: Ipv4(4); break;
                case 10 or 24 or 28 or 30: Ipv6(4); break;
                default: Note($"未知 Loopback 地址族 {family}"); break;
            }
        }

        private void Arp(int offset)
        {
            packet.LinkSummary = "ARP";
            if (!Need(offset, 8, Bytes.Length, "ARP")) return;
            int hlen = Bytes[offset + 4];
            int plen = Bytes[offset + 5];
            int length = 8 + (hlen + plen) * 2;
            if (!Need(offset, length, Bytes.Length, "ARP")) return;
            var fields = new List<PacketField>
            {
                F("硬件类型", U16(offset), offset, 2),
                F("协议类型", $"0x{U16(offset + 2):X4}", offset + 2, 2),
                F("操作", U16(offset + 6), offset + 6, 2)
            };
            if (hlen == 6 && plen == 4 && U16(offset + 2) == 0x0800)
            {
                packet.Source = Address(offset + 14, 4);
                packet.Destination = Address(offset + 24, 4);
                fields.Add(F("发送方 MAC", Mac(offset + 8), offset + 8, 6));
                fields.Add(F("发送方 IP", packet.Source, offset + 14, 4));
                fields.Add(F("目标 MAC", Mac(offset + 18), offset + 18, 6));
                fields.Add(F("目标 IP", packet.Destination, offset + 24, 4));
                packet.TransportSummary = $"{packet.Source} → {packet.Destination}";
            }
            packet.DecodedLayers.Add(new PacketLayer("ARP", offset, length, fields));
        }

        private void Ipv4(int offset)
        {
            packet.IpVersion = 4;
            if (!Need(offset, 20, Bytes.Length, "IPv4")) return;
            int headerLength = (Bytes[offset] & 15) * 4;
            int totalLength = U16(offset + 2);
            if (Bytes[offset] >> 4 != 4 || headerLength < 20 || totalLength < headerLength)
            {
                Note("IPv4 版本或长度字段无效");
                return;
            }
            if (!Need(offset, headerLength, Bytes.Length, "IPv4 选项")) return;
            int end = Math.Min(Bytes.Length, offset + totalLength);
            if (end < offset + totalLength) Note("IPv4 载荷截断");
            ushort fragmentation = U16(offset + 6);
            byte protocol = Bytes[offset + 9];
            packet.IpProtocol = protocol;
            packet.Source = Address(offset + 12, 4);
            packet.Destination = Address(offset + 16, 4);
            packet.TransportSummary = "";
            Layer("IPv4", offset, headerLength,
                F("版本", 4, offset, 1), F("首部长度", headerLength, offset, 1),
                F("总长度", totalLength, offset + 2, 2), F("标识", U16(offset + 4), offset + 4, 2),
                F("标志与分片偏移", $"0x{fragmentation:X4}", offset + 6, 2),
                F("TTL", Bytes[offset + 8], offset + 8, 1), F("上层协议", protocol, offset + 9, 1),
                F("首部校验和", $"0x{U16(offset + 10):X4}", offset + 10, 2),
                F("源地址", packet.Source, offset + 12, 4), F("目标地址", packet.Destination, offset + 16, 4));
            if ((fragmentation & 0x3fff) != 0)
            {
                Note($"IPv4 分片 · 偏移 {(fragmentation & 0x1fff) * 8} 字节");
                return;
            }
            Transport(protocol, offset + headerLength, end, end < offset + totalLength);
        }

        private void Ipv6(int offset)
        {
            packet.IpVersion = 6;
            if (!Need(offset, 40, Bytes.Length, "IPv6")) return;
            if (Bytes[offset] >> 4 != 6)
            {
                Note("IPv6 版本字段无效");
                return;
            }
            int payloadLength = U16(offset + 4);
            byte next = Bytes[offset + 6];
            packet.Source = Address(offset + 8, 16);
            packet.Destination = Address(offset + 24, 16);
            packet.TransportSummary = "";
            Layer("IPv6", offset, 40, F("版本", 6, offset, 1),
                F("流标签", U32(offset) & 0x000fffff, offset, 4),
                F("载荷长度", payloadLength, offset + 4, 2),
                F("下一头部", next, offset + 6, 1), F("跳数限制", Bytes[offset + 7], offset + 7, 1),
                F("源地址", packet.Source, offset + 8, 16), F("目标地址", packet.Destination, offset + 24, 16));
            int cursor = offset + 40;
            int end = Math.Min(Bytes.Length, cursor + payloadLength);
            bool truncated = end < cursor + payloadLength;
            if (truncated) Note("IPv6 载荷截断");
            if (payloadLength == 0 && next == 0)
            {
                Note("IPv6 Jumbo Payload 暂不解析");
                return;
            }
            for (int count = 0; next is 0 or 43 or 44 or 51 or 60; count++)
            {
                if (count == 16)
                {
                    Note("IPv6 扩展头超出解析上限");
                    return;
                }
                if (!Need(cursor, 2, end, "IPv6 扩展头")) return;
                byte type = next;
                next = Bytes[cursor];
                int length = type switch
                {
                    44 => 8,
                    51 => (Bytes[cursor + 1] + 2) * 4,
                    _ => (Bytes[cursor + 1] + 1) * 8
                };
                if (type == 51 && length < 12)
                {
                    Note("IPv6 AH 长度无效");
                    return;
                }
                if (!Need(cursor, length, end, "IPv6 扩展头")) return;
                if (type == 44)
                {
                    ushort bits = U16(cursor + 2);
                    Layer("IPv6 Fragment", cursor, length, F("下一头部", next, cursor, 1),
                        F("偏移（字节）", bits & 0xfff8, cursor + 2, 2),
                        F("后续分片", bits & 1, cursor + 2, 2), F("标识", U32(cursor + 4), cursor + 4, 4));
                    if ((bits & 0xfff9) != 0)
                    {
                        packet.IpProtocol = next;
                        Note("IPv6 分片");
                        return;
                    }
                }
                else
                {
                    Layer($"IPv6 扩展头 ({type})", cursor, length, F("下一头部", next, cursor, 1),
                        F("长度", length, cursor + 1, 1));
                }
                cursor += length;
            }
            packet.IpProtocol = next;
            Transport(next, cursor, end, truncated);
        }

        private void Transport(byte protocol, int offset, int end, bool truncated)
        {
            switch (protocol)
            {
                case 6: Tcp(offset, end, truncated); break;
                case 17: Udp(offset, end); break;
                case 1 or 58: Icmp(protocol, offset, end); break;
            }
        }

        private void Tcp(int offset, int end, bool truncated)
        {
            if (!Need(offset, 20, end, "TCP")) return;
            int headerLength = (Bytes[offset + 12] >> 4) * 4;
            if (headerLength < 20)
            {
                Note("TCP 首部长度无效");
                return;
            }
            if (!Need(offset, headerLength, end, "TCP 选项")) return;
            ushort sourcePort = U16(offset);
            ushort destinationPort = U16(offset + 2);
            var tcp = new TcpSegment(new Endpoint(packet.Source!, sourcePort), new Endpoint(packet.Destination!, destinationPort),
                U32(offset + 4), U32(offset + 8), Bytes[offset + 13], offset + headerLength,
                end - offset - headerLength, truncated);
            packet.Tcp = tcp;
            packet.SourcePort = sourcePort;
            packet.DestinationPort = destinationPort;
            packet.TransportSummary = $"{sourcePort} → {destinationPort} [{tcp.FlagNames}] Seq={tcp.Sequence} Ack={tcp.Acknowledgment} Len={tcp.PayloadLength}";
            Layer("TCP", offset, headerLength, F("源端口", sourcePort, offset, 2),
                F("目标端口", destinationPort, offset + 2, 2), F("序列号", tcp.Sequence, offset + 4, 4),
                F("确认号", tcp.Acknowledgment, offset + 8, 4), F("首部长度", headerLength, offset + 12, 1),
                F("标志", tcp.FlagNames, offset + 13, 1), F("窗口", U16(offset + 14), offset + 14, 2),
                F("校验和", $"0x{U16(offset + 16):X4}", offset + 16, 2));
        }

        private void Udp(int offset, int end)
        {
            if (!Need(offset, 8, end, "UDP")) return;
            int length = U16(offset + 4);
            if (length < 8)
            {
                Note("UDP 长度无效");
                return;
            }
            if (length > end - offset) Note("UDP 载荷截断");
            packet.SourcePort = U16(offset);
            packet.DestinationPort = U16(offset + 2);
            packet.TransportSummary = $"{packet.SourcePort} → {packet.DestinationPort} Len={length - 8}";
            Layer("UDP", offset, 8, F("源端口", packet.SourcePort.Value, offset, 2),
                F("目标端口", packet.DestinationPort.Value, offset + 2, 2), F("长度", length, offset + 4, 2),
                F("校验和", $"0x{U16(offset + 6):X4}", offset + 6, 2));
            int payload = Math.Min(end, offset + length);
            if (packet.SourcePort is 53 or 5353 || packet.DestinationPort is 53 or 5353)
                Dns(offset + 8, payload);
        }

        private void Dns(int offset, int end)
        {
            if (end - offset < 12) return;
            ushort id = U16(offset);
            ushort flags = U16(offset + 2);
            int questions = U16(offset + 4);
            int answers = U16(offset + 6);
            int authorities = U16(offset + 8);
            int additionals = U16(offset + 10);
            if (questions > 32 || answers > 64 || authorities > 64 || additionals > 64) return;
            bool response = (flags & 0x8000) != 0;
            if (questions + answers + authorities + additionals == 0 ||
                !response && (questions == 0 || answers != 0 || authorities != 0)) return;
            int cursor = offset + 12;
            var names = new List<string>();
            for (int i = 0; i < questions; i++)
            {
                if (ReadName(offset, end, ref cursor) is not { } name) return;
                if (cursor + 4 > end) return;
                names.Add(name);
                cursor += 4;
            }
            int questionsEnd = cursor;
            var records = new List<string>();
            var resolved = new List<DnsAddress>();
            for (int i = 0; i < answers + authorities + additionals; i++)
            {
                if (ReadName(offset, end, ref cursor) is not { } name) return;
                if (cursor + 10 > end) return;
                ushort type = U16(cursor);
                ushort recordClass = U16(cursor + 2);
                int dataLength = U16(cursor + 8);
                cursor += 10;
                if (dataLength > end - cursor) return;
                if (i < answers && DescribeRecord(offset, end, cursor, type, dataLength) is { } value)
                    records.Add($"{name} {value}");
                if (response && (flags & 15) == 0 && i < answers && recordClass == 1 && name.Length > 0 &&
                    (type, dataLength) is (1, 4) or (28, 16))
                    resolved.Add(new DnsAddress(new IPAddress(Bytes.AsSpan(cursor, dataLength)), name));
                cursor += dataLength;
            }
            if (cursor != end) return;
            string query = string.Join(", ", names);
            string summary = response ? "响应" : "查询";
            if (names.Count > 0) summary += $" {query}";
            if (records.Count > 0) summary += (names.Count > 0 ? " → " : " ") + string.Join(", ", records);
            packet.Dns = summary;
            packet.DnsAddresses = resolved;
            var fields = new List<PacketField>
            {
                F("事务 ID", $"0x{id:X4}", offset, 2),
                F("标志", response ? "响应" : "查询", offset + 2, 2),
                F("问题数", questions, offset + 4, 2),
                F("回答数", answers, offset + 6, 2)
            };
            if (questions > 0) fields.Add(F("查询", query, offset + 12, questionsEnd - (offset + 12)));
            if (records.Count > 0) fields.Add(F("回答", string.Join(", ", records), questionsEnd, cursor - questionsEnd));
            packet.DecodedLayers.Add(new PacketLayer("DNS", offset, cursor - offset, fields));
        }

        private string? DescribeRecord(int message, int end, int data, ushort type, int length)
        {
            if (type == 1 && length == 4) return new IPAddress(Bytes.AsSpan(data, 4)).ToString();
            if (type == 28 && length == 16) return new IPAddress(Bytes.AsSpan(data, 16)).ToString();
            if (type == 5)
            {
                int cursor = data;
                return ReadName(message, end, ref cursor) is { } target && cursor == data + length ? target : null;
            }
            return null;
        }

        private string? ReadName(int message, int end, ref int cursor)
        {
            var parts = new List<string>();
            int jumps = 0;
            int? resume = null;
            int position = cursor;
            while (position < end)
            {
                int length = Bytes[position];
                if (length == 0)
                {
                    cursor = resume ?? position + 1;
                    return string.Join(".", parts);
                }
                if ((length & 0xc0) == 0xc0)
                {
                    if (position + 1 >= end) return null;
                    int target = ((length & 0x3f) << 8) | Bytes[position + 1];
                    if (target >= position - message || jumps++ == 8) return null;
                    resume ??= position + 2;
                    position = message + target;
                    continue;
                }
                if ((length & 0xc0) != 0 || length > 63 || position + 1 + length > end || parts.Count == 32) return null;
                string label = System.Text.Encoding.ASCII.GetString(Bytes, position + 1, length);
                if (label.Any(c => c is < '!' or > '~')) return null;
                parts.Add(label);
                position += 1 + length;
                if (resume is null) cursor = position;
            }
            return null;
        }

        private void Icmp(byte protocol, int offset, int end)
        {
            string name = protocol == 1 ? "ICMP" : "ICMPv6";
            if (!Need(offset, 4, end, name)) return;
            byte type = Bytes[offset];
            byte code = Bytes[offset + 1];
            string echo = (protocol, type) switch
            {
                (1, 8) or (58, 128) => "Echo Request",
                (1, 0) or (58, 129) => "Echo Reply",
                _ => ""
            };
            packet.TransportSummary = $"{echo} Type={type} Code={code}".TrimStart();
            var fields = new List<PacketField>
            {
                F("类型", type, offset, 1), F("代码", code, offset + 1, 1),
                F("校验和", $"0x{U16(offset + 2):X4}", offset + 2, 2)
            };
            int length = 4;
            if (echo.Length != 0 && Need(offset, 8, end, name))
            {
                fields.Add(F("标识", U16(offset + 4), offset + 4, 2));
                fields.Add(F("序号", U16(offset + 6), offset + 6, 2));
                length = 8;
            }
            packet.DecodedLayers.Add(new PacketLayer(name, offset, length, fields));
        }

        private bool Need(int offset, int length, int end, string layer)
        {
            if (length <= end - offset) return true;
            Note($"{layer} 头部截断");
            return false;
        }

        private void Note(string message) => packet.Note = packet.Note is null ? message : $"{packet.Note} · {message}";
        private IPAddress Address(int offset, int length) => new(Bytes.AsSpan(offset, length));
        private ushort U16(int offset) => BinaryPrimitives.ReadUInt16BigEndian(Bytes.AsSpan(offset, 2));
        private uint U32(int offset) => BinaryPrimitives.ReadUInt32BigEndian(Bytes.AsSpan(offset, 4));
        private string Mac(int offset) => string.Join(":", Bytes.Skip(offset).Take(6).Select(b => b.ToString("X2")));
        private static PacketField F(string name, object value, int offset, int length) => new(name, value.ToString() ?? "", offset, length);
        private void Layer(string name, int offset, int length, params PacketField[] fields)
            => packet.DecodedLayers.Add(new PacketLayer(name, offset, length, fields));
    }
}

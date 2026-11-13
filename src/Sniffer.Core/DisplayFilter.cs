using System.Globalization;
using System.Net;

namespace Sniffer.Core;

public static class DisplayFilter
{
    public static Func<Packet, bool> Compile(string expression) => Compile(expression, false);

    public static Func<Packet, bool> CompileCapture(string expression) => Compile(expression, true);

    private static Func<Packet, bool> Compile(string expression, bool capture)
    {
        if (expression.Length > 512)
            throw new FormatException("过滤表达式最长 512 个字符。");
        return string.IsNullOrWhiteSpace(expression) ? _ => true : new Parser(expression, capture).Parse();
    }

    private sealed class Parser(string input, bool capture)
    {
        private int _position;

        public Func<Packet, bool> Parse()
        {
            var predicate = Or();
            Space();
            if (_position != input.Length) throw Error("预期 &&、|| 或表达式结束");
            return predicate;
        }

        private Func<Packet, bool> Or()
        {
            var result = And();
            while (Take("||") || capture && TakeWord("or"))
            {
                var left = result;
                var right = And();
                result = packet => left(packet) || right(packet);
            }
            return result;
        }

        private Func<Packet, bool> And()
        {
            var result = Unary();
            while (Take("&&") || capture && (TakeWord("and") || NextIsQualifier()))
            {
                var left = result;
                var right = Unary();
                result = packet => left(packet) && right(packet);
            }
            return result;
        }

        private Func<Packet, bool> Unary()
        {
            if (Take("!") || capture && TakeWord("not"))
            {
                var operand = Unary();
                return packet => !operand(packet);
            }
            if (Take("("))
            {
                var operand = Or();
                if (!Take(")")) throw Error("缺少右括号");
                return operand;
            }

            string token = Token().ToLowerInvariant();
            return token switch
            {
                "ipv4" or "ip" => packet => packet.IpVersion == 4,
                "ipv6" or "ip6" => packet => packet.IpVersion == 6,
                "tcp" => packet => packet.IpProtocol == 6,
                "udp" => packet => packet.IpProtocol == 17,
                "icmp" => packet => packet.IpProtocol == 1,
                "icmpv6" or "icmp6" => packet => packet.IpProtocol == 58,
                "arp" => packet => packet.LinkSummary == "ARP",
                "http" when !capture => packet => packet.Http is not null,
                "dns" when !capture => packet => packet.Dns is not null,
                "tls" when !capture => packet => packet.Tls is not null,
                "port" or "srcport" or "dstport" => Port(token),
                "pid" when !capture => Pid(),
                "stream" when !capture => Stream(),
                "ip.addr" or "ip.src" or "ip.dst" => Address(token),
                "host" when capture => Address("ip.addr"),
                "src" or "dst" when capture => Qualified(token),
                "http" or "dns" or "tls" or "pid" or "stream" => throw Error($"「{token}」请在显示过滤中使用"),
                _ => throw Error($"未知筛选字段「{token}」")
            };
        }

        private Func<Packet, bool> Port(string token)
        {
            if (!capture) RequireEquals();
            else Take("==");
            if (!ushort.TryParse(Token(), NumberStyles.None, CultureInfo.InvariantCulture, out ushort port))
                throw Error("端口应在 0 到 65535 之间");
            return token switch
            {
                "srcport" => packet => packet.SourcePort == port,
                "dstport" => packet => packet.DestinationPort == port,
                _ => packet => packet.SourcePort == port || packet.DestinationPort == port
            };
        }

        private Func<Packet, bool> Pid()
        {
            RequireEquals();
            if (!int.TryParse(Token(), NumberStyles.None, CultureInfo.InvariantCulture, out int pid) || pid <= 0)
                throw Error("PID 应为正整数");
            return packet => packet.Owners.Any(owner => owner.Pid == pid);
        }

        private Func<Packet, bool> Stream()
        {
            RequireEquals();
            if (!long.TryParse(Token(), NumberStyles.None, CultureInfo.InvariantCulture, out long id) || id <= 0)
                throw Error("会话编号应为正整数");
            return packet => packet.FlowId == id;
        }

        private Func<Packet, bool> Address(string token)
        {
            if (!capture) RequireEquals();
            else Take("==");
            if (!IPAddress.TryParse(Token(), out IPAddress? address))
                throw Error("地址应为有效的 IPv4 或 IPv6 地址");
            return token switch
            {
                "ip.src" => packet => address.Equals(packet.Source),
                "ip.dst" => packet => address.Equals(packet.Destination),
                _ => packet => address.Equals(packet.Source) || address.Equals(packet.Destination)
            };
        }

        private Func<Packet, bool> Qualified(string direction)
        {
            if (TakeWord("port")) return Port(direction + "port");
            if (TakeWord("host")) return Address("ip." + direction);
            throw Error("预期 port 或 host");
        }

        private bool NextIsQualifier() => IsWord("src") || IsWord("dst") || IsWord("port") || IsWord("host");

        private bool TakeWord(string word)
        {
            if (!IsWord(word)) return false;
            _position += word.Length;
            return true;
        }

        private bool IsWord(string word)
        {
            Space();
            int end = _position + word.Length;
            return input.AsSpan(_position).StartsWith(word, StringComparison.OrdinalIgnoreCase) &&
                (end == input.Length || !IsTokenCharacter(input[end]));
        }

        private void RequireEquals()
        {
            if (!Take("==")) throw Error("预期 ==");
        }

        private string Token()
        {
            Space();
            int start = _position;
            while (_position < input.Length && IsTokenCharacter(input[_position]))
                _position++;
            if (_position == start) throw Error("预期协议、字段或值");
            return input[start.._position];
        }

        private static bool IsTokenCharacter(char value) => char.IsAsciiLetterOrDigit(value) || value is '_' or '.' or ':' or '%';

        private bool Take(string value)
        {
            Space();
            if (!input.AsSpan(_position).StartsWith(value, StringComparison.Ordinal)) return false;
            _position += value.Length;
            return true;
        }

        private void Space()
        {
            while (_position < input.Length && char.IsWhiteSpace(input[_position])) _position++;
        }

        private FormatException Error(string message) => new($"{message}（第 {_position + 1} 个字符）");
    }
}

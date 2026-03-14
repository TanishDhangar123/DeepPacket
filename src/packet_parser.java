import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Java translation of packet_parser (packet_parser.h / packet_parser.cpp).
 * Parses raw packets into Ethernet, IP, TCP/UDP layers.
 */
public class packet_parser {

    // TCP Flag constants
    public static final byte TCP_FIN = 0x01;
    public static final byte TCP_SYN = 0x02;
    public static final byte TCP_RST = 0x04;
    public static final byte TCP_PSH = 0x08;
    public static final byte TCP_ACK = 0x10;
    public static final byte TCP_URG = 0x20;

    // Protocol numbers
    public static final byte PROTOCOL_ICMP = 1;
    public static final byte PROTOCOL_TCP = 6;
    public static final byte PROTOCOL_UDP = 17;

    // EtherType values
    public static final short ETHERTYPE_IPV4 = 0x0800;
    public static final short ETHERTYPE_IPV6 = (short) 0x86DD;
    public static final short ETHERTYPE_ARP = 0x0806;

    // -------------------------------------------------------------------------
    // ParsedPacket
    // -------------------------------------------------------------------------
    public static class ParsedPacket {
        public int timestamp_sec;
        public int timestamp_usec;
        public String src_mac = "";
        public String dest_mac = "";
        public int ether_type;

        public boolean has_ip;
        public int ip_version;
        public String src_ip = "";
        public String dest_ip = "";
        public byte protocol;
        public byte ttl;

        public boolean has_tcp;
        public boolean has_udp;
        public int src_port;
        public int dest_port;

        public byte tcp_flags;
        public long seq_number;
        public long ack_number;

        public int payload_length;
        public byte[] payload_data;
    }

    // -------------------------------------------------------------------------
    // parse
    // -------------------------------------------------------------------------
    public static boolean parse(PacketAnalyzer.RawPacket raw, ParsedPacket parsed) {
        parsed.timestamp_sec = raw.header.ts_sec;
        parsed.timestamp_usec = raw.header.ts_usec;
        parsed.src_mac = "";
        parsed.dest_mac = "";
        parsed.has_ip = false;
        parsed.has_tcp = false;
        parsed.has_udp = false;
        parsed.payload_length = 0;
        parsed.payload_data = null;

        byte[] data = raw.data;
        int len = data != null ? data.length : 0;
        int[] offsetRef = new int[]{0};

        if (!parseEthernet(data, len, parsed, offsetRef)) {
            return false;
        }

        if (parsed.ether_type == ETHERTYPE_IPV4) {
            if (!parseIPv4(data, len, parsed, offsetRef)) {
                return false;
            }
            if (parsed.protocol == PROTOCOL_TCP) {
                if (!parseTCP(data, len, parsed, offsetRef)) {
                    return false;
                }
            } else if (parsed.protocol == PROTOCOL_UDP) {
                if (!parseUDP(data, len, parsed, offsetRef)) {
                    return false;
                }
            }
        }

        int offset = offsetRef[0];
        if (offset < len) {
            parsed.payload_length = len - offset;
            parsed.payload_data = new byte[parsed.payload_length];
            System.arraycopy(data, offset, parsed.payload_data, 0, parsed.payload_length);
        }

        return true;
    }

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, int[] offsetRef) {
        final int ETH_HEADER_LEN = 14;
        if (len < ETH_HEADER_LEN) return false;

        parsed.dest_mac = macToString(data, 0);
        parsed.src_mac = macToString(data, 6);
        parsed.ether_type = ntohs(data, 12);
        offsetRef[0] = ETH_HEADER_LEN;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, int[] offsetRef) {
        final int MIN_IP_HEADER_LEN = 20;
        int offset = offsetRef[0];
        if (len < offset + MIN_IP_HEADER_LEN) return false;

        int versionIhl = data[offset] & 0xFF;
        parsed.ip_version = (versionIhl >> 4) & 0x0F;
        int ihl = (versionIhl & 0x0F) * 4;

        if (parsed.ip_version != 4) return false;
        if (ihl < MIN_IP_HEADER_LEN || len < offset + ihl) return false;

        parsed.ttl = data[offset + 8];
        parsed.protocol = data[offset + 9];
        parsed.src_ip = ipToString(data, offset + 12);
        parsed.dest_ip = ipToString(data, offset + 16);
        parsed.has_ip = true;
        offsetRef[0] = offset + ihl;
        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket parsed, int[] offsetRef) {
        final int MIN_TCP_HEADER_LEN = 20;
        int offset = offsetRef[0];
        if (len < offset + MIN_TCP_HEADER_LEN) return false;

        parsed.src_port = ntohs(data, offset);
        parsed.dest_port = ntohs(data, offset + 2);
        parsed.seq_number = ntohl(data, offset + 4) & 0xFFFFFFFFL;
        parsed.ack_number = ntohl(data, offset + 8) & 0xFFFFFFFFL;
        int dataOffset = ((data[offset + 12] & 0xFF) >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;
        parsed.tcp_flags = data[offset + 13];

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < offset + tcpHeaderLen) return false;

        parsed.has_tcp = true;
        offsetRef[0] = offset + tcpHeaderLen;
        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket parsed, int[] offsetRef) {
        final int UDP_HEADER_LEN = 8;
        int offset = offsetRef[0];
        if (len < offset + UDP_HEADER_LEN) return false;

        parsed.src_port = ntohs(data, offset);
        parsed.dest_port = ntohs(data, offset + 2);
        parsed.has_udp = true;
        offsetRef[0] = offset + UDP_HEADER_LEN;
        return true;
    }

    // Network byte order (big-endian) to host
    private static int ntohs(byte[] data, int off) {
        return ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
    }

    private static int ntohl(byte[] data, int off) {
        return ((data[off] & 0xFF) << 24) | ((data[off + 1] & 0xFF) << 16)
                | ((data[off + 2] & 0xFF) << 8) | (data[off + 3] & 0xFF);
    }

    public static String macToString(byte[] mac, int off) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", mac[off + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int off) {
        return (data[off] & 0xFF) + "." + (data[off + 1] & 0xFF) + "."
                + (data[off + 2] & 0xFF) + "." + (data[off + 3] & 0xFF);
    }

    public static String protocolToString(byte protocol) {
        switch (protocol & 0xFF) {
            case PROTOCOL_ICMP: return "ICMP";
            case PROTOCOL_TCP:  return "TCP";
            case PROTOCOL_UDP:  return "UDP";
            default: return "Unknown(" + (protocol & 0xFF) + ")";
        }
    }

    public static String tcpFlagsToString(byte flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_RST) != 0) sb.append("RST ");
        if ((flags & TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_URG) != 0) sb.append("URG ");
        if (sb.length() > 0) sb.setLength(sb.length() - 1);
        return sb.length() == 0 ? "none" : sb.toString();
    }
}

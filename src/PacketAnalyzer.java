import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Java translation of PacketAnalyzer pcap_reader (pcap_reader.h / pcap_reader.cpp).
 *
 * Provides PCAP file reading: global header, packet headers, and raw packet bytes.
 */
public class PacketAnalyzer {

    // Magic numbers for PCAP files
    private static final int PCAP_MAGIC_NATIVE = 0xa1b2c3d4;  // Native (little-endian)
    private static final int PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;  // Swapped byte order

    // -------------------------------------------------------------------------
    // PcapGlobalHeader (24 bytes)
    // -------------------------------------------------------------------------
    public static class PcapGlobalHeader {
        public int magic_number;
        public short version_major;
        public short version_minor;
        public int thiszone;
        public int sigfigs;
        public int snaplen;
        public int network;

        public byte[] toByteArray() {
            ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
            buf.putInt(magic_number);
            buf.putShort(version_major);
            buf.putShort(version_minor);
            buf.putInt(thiszone);
            buf.putInt(sigfigs);
            buf.putInt(snaplen);
            buf.putInt(network);
            return buf.array();
        }

        public static PcapGlobalHeader fromByteArray(byte[] bytes) {
            if (bytes == null || bytes.length < 24) return null;
            ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            PcapGlobalHeader h = new PcapGlobalHeader();
            h.magic_number = buf.getInt();
            h.version_major = buf.getShort();
            h.version_minor = buf.getShort();
            h.thiszone = buf.getInt();
            h.sigfigs = buf.getInt();
            h.snaplen = buf.getInt();
            h.network = buf.getInt();
            return h;
        }
    }

    // -------------------------------------------------------------------------
    // PcapPacketHeader (16 bytes)
    // -------------------------------------------------------------------------
    public static class PcapPacketHeader {
        public int ts_sec;
        public int ts_usec;
        public int incl_len;
        public int orig_len;

        public byte[] toByteArray() {
            ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
            buf.putInt(ts_sec);
            buf.putInt(ts_usec);
            buf.putInt(incl_len);
            buf.putInt(orig_len);
            return buf.array();
        }
    }

    // -------------------------------------------------------------------------
    // RawPacket
    // -------------------------------------------------------------------------
    public static class RawPacket {
        public PcapPacketHeader header = new PcapPacketHeader();
        public byte[] data = new byte[0];
    }

    // -------------------------------------------------------------------------
    // PcapReader
    // -------------------------------------------------------------------------
    public static class PcapReader {
        private RandomAccessFile file;
        private PcapGlobalHeader globalHeader = new PcapGlobalHeader();
        private boolean needsByteSwap;

        public PcapReader() {
        }

        public boolean open(String filename) {
            close();

            try {
                file = new RandomAccessFile(filename, "r");
            } catch (FileNotFoundException e) {
                System.err.println("Error: Could not open file: " + filename);
                return false;
            }

            try {
                byte[] headerBytes = new byte[24];
                if (file.read(headerBytes) != 24) {
                    System.err.println("Error: Could not read PCAP global header");
                    close();
                    return false;
                }

                ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN);
                globalHeader.magic_number = buf.getInt();
                globalHeader.version_major = buf.getShort();
                globalHeader.version_minor = buf.getShort();
                globalHeader.thiszone = buf.getInt();
                globalHeader.sigfigs = buf.getInt();
                globalHeader.snaplen = buf.getInt();
                globalHeader.network = buf.getInt();

                if (globalHeader.magic_number == PCAP_MAGIC_NATIVE) {
                    needsByteSwap = false;
                } else if ((globalHeader.magic_number & 0xFFFFFFFFL) == (PCAP_MAGIC_SWAPPED & 0xFFFFFFFFL)) {
                    needsByteSwap = true;
                    globalHeader.version_major = swap16(globalHeader.version_major);
                    globalHeader.version_minor = swap16(globalHeader.version_minor);
                    globalHeader.snaplen = swap32(globalHeader.snaplen);
                    globalHeader.network = swap32(globalHeader.network);
                } else {
                    System.err.printf("Error: Invalid PCAP magic number: 0x%08X%n",
                            globalHeader.magic_number & 0xFFFFFFFFL);
                    close();
                    return false;
                }
            } catch (IOException e) {
                System.err.println("Error reading PCAP header: " + e.getMessage());
                close();
                return false;
            }

            System.out.println("Opened PCAP file: " + filename);
            System.out.printf("  Version: %d.%d%n", globalHeader.version_major & 0xFFFF,
                    globalHeader.version_minor & 0xFFFF);
            System.out.println("  Snaplen: " + (globalHeader.snaplen & 0xFFFFFFFFL) + " bytes");
            int net = globalHeader.network & 0xFFFFFFFF;
            System.out.println("  Link type: " + net + (net == 1 ? " (Ethernet)" : ""));

            return true;
        }

        public void close() {
            if (file != null) {
                try {
                    file.close();
                } catch (IOException ignored) {
                }
                file = null;
            }
            needsByteSwap = false;
        }

        public boolean readNextPacket(RawPacket packet) {
            if (file == null) {
                return false;
            }

            try {
                byte[] headerBytes = new byte[16];
                if (file.read(headerBytes) != 16) {
                    return false;
                }

                ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN);
                packet.header.ts_sec = buf.getInt();
                packet.header.ts_usec = buf.getInt();
                packet.header.incl_len = buf.getInt();
                packet.header.orig_len = buf.getInt();

                if (needsByteSwap) {
                    packet.header.ts_sec = swap32(packet.header.ts_sec);
                    packet.header.ts_usec = swap32(packet.header.ts_usec);
                    packet.header.incl_len = swap32(packet.header.incl_len);
                    packet.header.orig_len = swap32(packet.header.orig_len);
                }

                int inclLen = packet.header.incl_len & 0xFFFFFFFF;
                if (inclLen > (globalHeader.snaplen & 0xFFFFFFFFL) || inclLen > 65535) {
                    System.err.println("Error: Invalid packet length: " + inclLen);
                    return false;
                }

                packet.data = new byte[inclLen];
                if (file.read(packet.data) != inclLen) {
                    System.err.println("Error: Could not read packet data");
                    return false;
                }

                return true;
            } catch (IOException e) {
                return false;
            }
        }

        public PcapGlobalHeader getGlobalHeader() {
            return globalHeader;
        }

        public boolean isOpen() {
            return file != null;
        }

        public boolean needsByteSwap() {
            return needsByteSwap;
        }

        private static short swap16(short value) {
            return (short) (((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8));
        }

        private static int swap32(int value) {
            return ((value & 0xFF000000) >>> 24) |
                    ((value & 0x00FF0000) >>> 8) |
                    ((value & 0x0000FF00) << 8) |
                    ((value & 0x000000FF) << 24);
        }
    }
}

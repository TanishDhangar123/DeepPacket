import java.io.FileOutputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Java translation of {@code dpi_engine.cpp}.
 *
 * <p>This class mirrors the structure and logic of the original C++ {@code DPI::DPIEngine}
 * implementation, adapted to Java threading and I/O primitives.</p>
 *
 * <p>NOTE: This translation assumes the existence of several supporting types which must be
 * implemented separately or ported from C++:</p>
 *
 * <ul>
 *   <li>{@code RuleManager} (rule loading, blocking/unblocking IPs, apps, domains, ports)</li>
 *   <li>{@code FPManager} (fast-path workers, queues, statistics, classification report)</li>
 *   <li>{@code LBManager} and {@code LoadBalancer} (load balancer workers and their stats)</li>
 *   <li>{@code PacketJob} (packet metadata and payload, including five-tuple and offsets)</li>
 *   <li>{@code PacketAction} enum with at least {@code DROP} and a "forward" action</li>
 *   <li>{@code DPIStats} equivalent, if you prefer a shared type instead of the inner {@link Stats}</li>
 *   <li>{@code PacketAnalyzer} namespace with:
 *       <ul>
 *         <li>{@code PcapReader} (open/close/readNextPacket/getGlobalHeader)</li>
 *         <li>{@code RawPacket} (pcap header + raw bytes)</li>
 *         <li>{@code ParsedPacket} (IP/TCP/UDP flags, ports, protocol, IP strings)</li>
 *         <li>{@code PcapGlobalHeader} and {@code PcapPacketHeader} (serialisable to bytes)</li>
 *         <li>{@code PacketParser} with static {@code parse(RawPacket, ParsedPacket)}</li>
 *       </ul>
 *   </li>
 *   <li>{@code AppType} enum and {@code appTypeToString(AppType)} helper</li>
 *   <li>{@code GlobalConnectionTable} (already provided in {@code ConnectionTracker.java})</li>
 * </ul>
 */
public class DPIEngine {

    /**
     * Configuration equivalent to {@code DPI::Config} in the C++ code.
     */
    public static class Config {
        public int num_load_balancers;
        public int fps_per_lb;
        public String rules_file = "";
    }

    /**
     * Statistics equivalent to {@code DPIStats} in the C++ implementation.
     */
    public static class Stats {
        public final AtomicLong total_packets = new AtomicLong();
        public final AtomicLong total_bytes = new AtomicLong();
        public final AtomicLong tcp_packets = new AtomicLong();
        public final AtomicLong udp_packets = new AtomicLong();
        public final AtomicLong forwarded_packets = new AtomicLong();
        public final AtomicLong dropped_packets = new AtomicLong();
    }

    @FunctionalInterface
    public interface OutputCallback {
        void handle(PacketJob job, PacketAction action);
    }

    private final Config config;
    private final BlockingQueue<PacketJob> outputQueue = new LinkedBlockingQueue<>(10_000);

    private volatile boolean running = false;
    private volatile boolean processingComplete = false;

    private Thread outputThread;
    private Thread readerThread;

    private RuleManager ruleManager;
    private FPManager fpManager;
    private LBManager lbManager;
    private GlobalConnectionTable globalConnTable;

    private final Object outputLock = new Object();
    private FileOutputStream outputFile;

    private final Stats stats = new Stats();

    public DPIEngine(Config config) {
        this.config = config;

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║   Load Balancers:    %3d                                       ║%n",
                config.num_load_balancers);
        System.out.printf("║   FPs per LB:        %3d                                       ║%n",
                config.fps_per_lb);
        System.out.printf("║   Total FP threads:  %3d                                       ║%n",
                (config.num_load_balancers * config.fps_per_lb));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    public void close() {
        stop();
    }

    public boolean initialize() {
        // Create rule manager
        ruleManager = new RuleManager();

        // Load rules if specified
        if (config.rules_file != null && !config.rules_file.isEmpty()) {
            ruleManager.loadRules(config.rules_file);
        }

        // Create output callback
        OutputCallback outputCb = (job, action) -> handleOutput(job, action);

        // Create FP manager (creates FP threads and their queues)
        int totalFps = config.num_load_balancers * config.fps_per_lb;
        fpManager = new FPManager(totalFps, ruleManager, outputCb);

        // Create LB manager (creates LB threads, connects to FP queues)
        lbManager = new LBManager(
                config.num_load_balancers,
                config.fps_per_lb,
                fpManager.getQueuePtrs()
        );

        // Create global connection table
        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running) {
            return;
        }

        running = true;
        processingComplete = false;

        // Start output thread
        outputThread = new Thread(this::outputThreadFunc, "dpi-output-thread");
        outputThread.start();

        // Start FP threads
        fpManager.startAll();

        // Start LB threads
        lbManager.startAll();

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running) {
            return;
        }

        running = false;

        // Stop LB threads first (they feed FPs)
        if (lbManager != null) {
            lbManager.stopAll();
        }

        // Stop FP threads
        if (fpManager != null) {
            fpManager.stopAll();
        }

        // Stop output thread
        if (outputThread != null && outputThread.isAlive()) {
            outputThread.interrupt();
            try {
                outputThread.join();
            } catch (InterruptedException ignored) {
            }
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    private void waitForCompletion() {
        // Wait for reader to finish
        if (readerThread != null && readerThread.isAlive()) {
            try {
                readerThread.join();
            } catch (InterruptedException ignored) {
            }
        }

        // Wait a bit for queues to drain
        try {
            Thread.sleep(500);
        } catch (InterruptedException ignored) {
        }

        // Signal completion
        processingComplete = true;
    }

    public boolean processFile(String inputFile, String outputFilePath) {

        System.out.println();
        System.out.println("[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFilePath);
        System.out.println();

        // Initialize if not already done
        if (ruleManager == null) {
            if (!initialize()) {
                return false;
            }
        }

        // Open output file
        try {
            outputFile = new FileOutputStream(outputFilePath);
        } catch (IOException e) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        // Start processing threads
        start();

        // Start reader thread
        readerThread = new Thread(() -> readerThreadFunc(inputFile), "dpi-reader-thread");
        readerThread.start();

        // Wait for completion
        waitForCompletion();

        // Give some time for final packets to process
        try {
            Thread.sleep(200);
        } catch (InterruptedException ignored) {
        }

        // Stop all threads
        stop();

        // Close output file
        if (outputFile != null) {
            try {
                outputFile.close();
            } catch (IOException ignored) {
            }
        }

        // Print final report
        System.out.println(generateReport());
        System.out.println(generateClassificationReport());

        return true;
    }

    private void readerThreadFunc(String inputFile) {
        PacketAnalyzer.PcapReader reader = new PacketAnalyzer.PcapReader();

        if (!reader.open(inputFile)) {
            System.err.println("[Reader] Error: Cannot open input file");
            return;
        }

        // Write PCAP header to output
        writeOutputHeader(reader.getGlobalHeader());

        PacketAnalyzer.RawPacket raw = new PacketAnalyzer.RawPacket();
        packet_parser.ParsedPacket parsed = new packet_parser.ParsedPacket();
        long packetId = 0;

        System.out.println("[Reader] Starting packet processing...");

        while (reader.readNextPacket(raw)) {
            // Parse the packet
            if (!packet_parser.parse(raw, parsed)) {
                continue;  // Skip unparseable packets
            }

            // Only process IP packets with TCP/UDP
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
                continue;
            }

            // Create packet job
            PacketJob job = createPacketJob(raw, parsed, packetId++);

            // Update global stats
            stats.total_packets.incrementAndGet();
            stats.total_bytes.addAndGet(raw.data.length);

            if (parsed.has_tcp) {
                stats.tcp_packets.incrementAndGet();
            } else if (parsed.has_udp) {
                stats.udp_packets.incrementAndGet();
            }

            // Send to appropriate LB based on hash
            LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
            lb.getInputQueue().add(job);
        }

        System.out.println("[Reader] Finished reading " + packetId + " packets");
        reader.close();
    }

    private PacketJob createPacketJob(PacketAnalyzer.RawPacket raw,
                                      packet_parser.ParsedPacket parsed,
                                      long packetId) {
        PacketJob job = new PacketJob();
        job.packet_id = packetId;
        job.ts_sec = raw.header.ts_sec;
        job.ts_usec = raw.header.ts_usec;

        // Set five-tuple - parse IP addresses from string back to uint32
        java.util.function.Function<String, Integer> parseIP = ip -> {
            long result = 0;
            int octet = 0;
            int shift = 0;
            for (int i = 0; i < ip.length(); i++) {
                char c = ip.charAt(i);
                if (c == '.') {
                    result |= ((long) octet << shift);
                    shift += 8;
                    octet = 0;
                } else if (c >= '0' && c <= '9') {
                    octet = octet * 10 + (c - '0');
                }
            }
            result |= ((long) octet << shift);
            return (int) (result & 0xFFFFFFFFL);
        };

        job.tuple.src_ip = parseIP.apply(parsed.src_ip);
        job.tuple.dst_ip = parseIP.apply(parsed.dest_ip);
        job.tuple.src_port = parsed.src_port;
        job.tuple.dst_port = parsed.dest_port;
        job.tuple.protocol = parsed.protocol;

        // TCP flags
        job.tcp_flags = parsed.tcp_flags;

        // Copy packet data
        job.data = raw.data.clone();

        // Calculate offsets
        job.eth_offset = 0;
        job.ip_offset = 14;  // Ethernet header is 14 bytes

        if (job.data.length > 14) {
            int ipIhl = job.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transport_offset = 14 + ipHeaderLen;

            if (parsed.has_tcp && job.data.length > job.transport_offset) {
                int tcpDataOffset = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payload_offset = job.transport_offset + tcpHeaderLen;
            } else if (parsed.has_udp) {
                job.payload_offset = job.transport_offset + 8;  // UDP header is 8 bytes
            }

            if (job.payload_offset < job.data.length) {
                job.payload_length = job.data.length - job.payload_offset;
                job.payload_data = new byte[job.payload_length];
                System.arraycopy(job.data, job.payload_offset, job.payload_data, 0, job.payload_length);
            }
        }

        return job;
    }

    private void outputThreadFunc() {
        while (running || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) {
                    writeOutputPacket(job);
                }
            } catch (InterruptedException e) {
                if (!running) {
                    break;
                }
            }
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.dropped_packets.incrementAndGet();
            return;
        }

        stats.forwarded_packets.incrementAndGet();
        outputQueue.add(job);
    }

    private boolean writeOutputHeader(PacketAnalyzer.PcapGlobalHeader header) {
        synchronized (outputLock) {
            if (outputFile == null) {
                return false;
            }
            try {
                outputFile.write(header.toByteArray());
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }

    private void writeOutputPacket(PacketJob job) {
        synchronized (outputLock) {
            if (outputFile == null) {
                return;
            }

            PacketAnalyzer.PcapPacketHeader pktHeader = new PacketAnalyzer.PcapPacketHeader();
            pktHeader.ts_sec = job.ts_sec;
            pktHeader.ts_usec = job.ts_usec;
            pktHeader.incl_len = job.data.length;
            pktHeader.orig_len = job.data.length;

            try {
                outputFile.write(pktHeader.toByteArray());
                outputFile.write(job.data);
            } catch (IOException ignored) {
            }
        }
    }

    // -------------------------------------------------------------------------
    // Rule Management API
    // -------------------------------------------------------------------------

    public void blockIP(String ip) {
        if (ruleManager != null) {
            ruleManager.blockIP(ip);
        }
    }

    public void unblockIP(String ip) {
        if (ruleManager != null) {
            ruleManager.unblockIP(ip);
        }
    }

    public void blockApp(AppType app) {
        if (ruleManager != null) {
            ruleManager.blockApp(app);
        }
    }

    public void blockApp(String appName) {
        for (int i = 0; i < (int) AppType.APP_COUNT; i++) {
            AppType app = AppType.fromOrdinal(i);
            if (appTypeToString(app).equals(appName)) {
                blockApp(app);
                return;
            }
        }
        System.err.println("[DPIEngine] Unknown app: " + appName);
    }

    public void unblockApp(AppType app) {
        if (ruleManager != null) {
            ruleManager.unblockApp(app);
        }
    }

    public void unblockApp(String appName) {
        for (int i = 0; i < (int) AppType.APP_COUNT; i++) {
            AppType app = AppType.fromOrdinal(i);
            if (appTypeToString(app).equals(appName)) {
                unblockApp(app);
                return;
            }
        }
    }

    public void blockDomain(String domain) {
        if (ruleManager != null) {
            ruleManager.blockDomain(domain);
        }
    }

    public void unblockDomain(String domain) {
        if (ruleManager != null) {
            ruleManager.unblockDomain(domain);
        }
    }

    public boolean loadRules(String filename) {
        if (ruleManager != null) {
            return ruleManager.loadRules(filename);
        }
        return false;
    }

    public boolean saveRules(String filename) {
        if (ruleManager != null) {
            return ruleManager.saveRules(filename);
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Reporting
    // -------------------------------------------------------------------------

    public String generateReport() {
        StringBuilder ss = new StringBuilder();

        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                    DPI ENGINE STATISTICS                      ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        ss.append("║ PACKET STATISTICS                                             ║\n");
        ss.append(String.format("║   Total Packets:      %12d                        ║\n",
                stats.total_packets.get()));
        ss.append(String.format("║   Total Bytes:        %12d                        ║\n",
                stats.total_bytes.get()));
        ss.append(String.format("║   TCP Packets:        %12d                        ║\n",
                stats.tcp_packets.get()));
        ss.append(String.format("║   UDP Packets:        %12d                        ║\n",
                stats.udp_packets.get()));

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FILTERING STATISTICS                                          ║\n");
        ss.append(String.format("║   Forwarded:          %12d                        ║\n",
                stats.forwarded_packets.get()));
        ss.append(String.format("║   Dropped/Blocked:    %12d                        ║\n",
                stats.dropped_packets.get()));

        long totalPackets = stats.total_packets.get();
        if (totalPackets > 0) {
            double dropRate = 100.0 * stats.dropped_packets.get() / (double) totalPackets;
            ss.append(String.format("║   Drop Rate:          %11.2f%%                        ║\n",
                    dropRate));
        }

        if (lbManager != null) {
            LBManager.AggregatedStats lbStats = lbManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ LOAD BALANCER STATISTICS                                      ║\n");
            ss.append(String.format("║   LB Received:        %12d                        ║\n",
                    lbStats.total_received));
            ss.append(String.format("║   LB Dispatched:      %12d                        ║\n",
                    lbStats.total_dispatched));
        }

        if (fpManager != null) {
            FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ FAST PATH STATISTICS                                          ║\n");
            ss.append(String.format("║   FP Processed:       %12d                        ║\n",
                    fpStats.total_processed));
            ss.append(String.format("║   FP Forwarded:       %12d                        ║\n",
                    fpStats.total_forwarded));
            ss.append(String.format("║   FP Dropped:         %12d                        ║\n",
                    fpStats.total_dropped));
            ss.append(String.format("║   Active Connections: %12d                        ║\n",
                    fpStats.total_connections));
        }

        if (ruleManager != null) {
            RuleManager.RuleStats ruleStats = ruleManager.getStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ BLOCKING RULES                                                ║\n");
            ss.append(String.format("║   Blocked IPs:        %12d                        ║\n",
                    ruleStats.blocked_ips));
            ss.append(String.format("║   Blocked Apps:       %12d                        ║\n",
                    ruleStats.blocked_apps));
            ss.append(String.format("║   Blocked Domains:    %12d                        ║\n",
                    ruleStats.blocked_domains));
            ss.append(String.format("║   Blocked Ports:      %12d                        ║\n",
                    ruleStats.blocked_ports));
        }

        ss.append("╚══════════════════════════════════════════════════════════════╝\n");

        return ss.toString();
    }

    public String generateClassificationReport() {
        if (fpManager != null) {
            return fpManager.generateClassificationReport();
        }
        return "";
    }

    public Stats getStats() {
        return stats;
    }

    public void printStatus() {
        System.out.println("\n--- Live Status ---");
        System.out.println("Packets: " + stats.total_packets.get()
                + " | Forwarded: " + stats.forwarded_packets.get()
                + " | Dropped: " + stats.dropped_packets.get());

        if (fpManager != null) {
            FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            System.out.println("Connections: " + fpStats.total_connections);
        }
    }

    /**
     * Placeholder – implement or replace with a real helper that maps AppType to string.
     */
    private String appTypeToString(AppType appType) {
        return appType.toString();
    }
}


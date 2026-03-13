import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Java translation of {@code FastPathProcessor} from {@code fast_path.cpp}.
 *
 * Each fast-path thread:
 *  - Receives {@code PacketJob} instances from its input queue
 *  - Tracks per-connection state via {@code ConnectionTracker}
 *  - Performs DPI classification (SNI/HTTP host/DNS/port-based)
 *  - Consults {@code RuleManager} to decide whether to forward or drop
 *  - Invokes an output callback for packets to be forwarded
 *
 * This class depends on several types that must exist in Java:
 *  - {@code PacketJob}, {@code PacketAction}
 *  - {@code FiveTuple}, {@code Connection}, {@code AppType}
 *  - {@code ConnectionTracker} (already ported)
 *  - {@code RuleManager} and {@code RuleManager.BlockReason}
 *  - {@code SNIExtractor}, {@code HTTPHostExtractor}, {@code DNSExtractor}
 *  - {@code sniToAppType(String)} helper and {@code appTypeToString(AppType)}
 */
public class FastPathProcessor {

    public static class FPStats {
        public long packets_processed;
        public long packets_forwarded;
        public long packets_dropped;
        public long connections_tracked;
        public long sni_extractions;
        public long classification_hits;
    }

    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10_000);
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;

    // Output callback: (job, action) → void
    private final BiConsumer<PacketJob, PacketAction> outputCallback;

    private final AtomicLong packetsProcessed = new AtomicLong();
    private final AtomicLong packetsForwarded = new AtomicLong();
    private final AtomicLong packetsDropped = new AtomicLong();
    private final AtomicLong sniExtractions = new AtomicLong();
    private final AtomicLong classificationHits = new AtomicLong();

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public FastPathProcessor(int fpId,
                             RuleManager ruleManager,
                             BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId = fpId;
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
        this.connTracker = new ConnectionTracker(fpId, /*max_connections=*/10_000L);
    }

    public void start() {
        if (running.get()) {
            return;
        }
        running.set(true);
        thread = new Thread(this::run, "fp-thread-" + fpId);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running.get()) {
            return;
        }
        running.set(false);
        inputQueue.shutdown();
        if (thread != null && thread.isAlive()) {
            try {
                thread.join();
            } catch (InterruptedException ignored) {
            }
        }
        System.out.println("[FP" + fpId + "] Stopped (processed "
                + packetsProcessed.get() + " packets)");
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public int getId() {
        return fpId;
    }

    public boolean isRunning() {
        return running.get();
    }

    public FPStats getStats() {
        FPStats stats = new FPStats();
        stats.packets_processed = packetsProcessed.get();
        stats.packets_forwarded = packetsForwarded.get();
        stats.packets_dropped = packetsDropped.get();
        stats.connections_tracked = connTracker.getActiveCount();
        stats.sni_extractions = sniExtractions.get();
        stats.classification_hits = classificationHits.get();
        return stats;
    }

    private void run() {
        while (running.get()) {
            PacketJob job = inputQueue.popWithTimeout(100);
            if (job == null) {
                // Periodically cleanup stale connections
                connTracker.cleanupStale(java.time.Duration.ofSeconds(300));
                continue;
            }

            packetsProcessed.incrementAndGet();

            PacketAction action = processPacket(job);

            if (outputCallback != null) {
                outputCallback.accept(job, action);
            }

            if (action == PacketAction.DROP) {
                packetsDropped.incrementAndGet();
            } else {
                packetsForwarded.incrementAndGet();
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn == null) {
            return PacketAction.FORWARD;
        }

        boolean isOutbound = true;
        connTracker.updateConnection(conn, job.data.length, isOutbound);

        if (job.tuple.protocol == 6) {
            updateTCPState(conn, job.tcp_flags);
        }

        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        if (conn.state != ConnectionState.CLASSIFIED && job.payload_length > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payload_length == 0 || job.payload_offset >= job.data.length) {
            return;
        }

        // Try TLS SNI extraction first
        if (tryExtractSNI(job, conn)) {
            return;
        }

        // Try HTTP Host extraction
        if (tryExtractHTTPHost(job, conn)) {
            return;
        }

        // DNS
        if (job.tuple.dst_port == 53 || job.tuple.src_port == 53) {
            String domain = DNSExtractor.extractQuery(job.payload_data, job.payload_length);
            if (domain != null) {
                connTracker.classifyConnection(conn, AppType.DNS, domain);
                return;
            }
        }

        // Port-based fallback
        if (job.tuple.dst_port == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.tuple.dst_port == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        if (job.tuple.dst_port != 443 && job.payload_length < 50) {
            return false;
        }
        if (job.payload_offset >= job.data.length || job.payload_length == 0) {
            return false;
        }

        String sni = SNIExtractor.extract(job.payload_data, job.payload_length);
        if (sni != null) {
            sniExtractions.incrementAndGet();
            AppType app = sniToAppType(sni);
            connTracker.classifyConnection(conn, app, sni);

            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        if (job.tuple.dst_port != 80) {
            return false;
        }
        if (job.payload_offset >= job.data.length || job.payload_length == 0) {
            return false;
        }

        String host = HTTPHostExtractor.extract(job.payload_data, job.payload_length);
        if (host != null) {
            AppType app = sniToAppType(host);
            connTracker.classifyConnection(conn, app, host);

            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) {
            return PacketAction.FORWARD;
        }

        long srcIp = job.tuple.src_ip;

        RuleManager.BlockReason reason = ruleManager.shouldBlock(
                srcIp,
                job.tuple.dst_port,
                conn.app_type,
                conn.sni
        );

        if (reason != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("[FP").append(fpId).append("] BLOCKED packet: ");
            switch (reason.type) {
                case IP:
                    sb.append("IP ").append(reason.detail);
                    break;
                case APP:
                    sb.append("App ").append(reason.detail);
                    break;
                case DOMAIN:
                    sb.append("Domain ").append(reason.detail);
                    break;
                case PORT:
                    sb.append("Port ").append(reason.detail);
                    break;
            }
            System.out.println(sb);

            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection conn, byte tcpFlags) {
        final byte SYN = 0x02;
        final byte ACK = 0x10;
        final byte FIN = 0x01;
        final byte RST = 0x04;

        if ((tcpFlags & SYN) != 0) {
            if ((tcpFlags & ACK) != 0) {
                conn.syn_ack_seen = true;
            } else {
                conn.syn_seen = true;
            }
        }

        if (conn.syn_seen && conn.syn_ack_seen && (tcpFlags & ACK) != 0) {
            if (conn.state == ConnectionState.NEW) {
                conn.state = ConnectionState.ESTABLISHED;
            }
        }

        if ((tcpFlags & FIN) != 0) {
            conn.fin_seen = true;
        }

        if ((tcpFlags & RST) != 0) {
            conn.state = ConnectionState.CLOSED;
        }

        if (conn.fin_seen && (tcpFlags & ACK) != 0) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    // Placeholder: implement according to your C++ mapping logic
    private AppType sniToAppType(String hostOrSni) {
        return AppType.UNKNOWN;
    }
}


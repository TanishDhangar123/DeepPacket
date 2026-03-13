import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

/**
 * Java translation of connection_tracker.cpp.
 *
 * NOTE: This class assumes the existence of the following types which should
 * be ported from your C++ code or implemented separately:
 * - FiveTuple (with a reverse() method and proper equals/hashCode)
 * - Connection (fields: tuple, state, first_seen, last_seen, packets_in,
 *              packets_out, bytes_in, bytes_out, app_type, sni, action)
 * - AppType
 * - PacketAction (with value DROP)
 * - ConnectionState (values NEW, CLASSIFIED, BLOCKED, CLOSED)
 * - appTypeToString(AppType) helper (can be a static utility method)
 */
public class ConnectionTracker {

    private final int fp_id_;
    private final long max_connections_;

    private final Map<FiveTuple, Connection> connections_ = new HashMap<>();

    private long total_seen_ = 0;
    private long classified_count_ = 0;
    private long blocked_count_ = 0;

    public static class TrackerStats {
        public long active_connections;
        public long total_connections_seen;
        public long classified_connections;
        public long blocked_connections;
    }

    public ConnectionTracker(int fp_id, long max_connections) {
        this.fp_id_ = fp_id;
        this.max_connections_ = max_connections;
    }

    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection existing = connections_.get(tuple);
        if (existing != null) {
            return existing;
        }

        // Evict oldest if needed
        if (connections_.size() >= max_connections_) {
            evictOldest();
        }

        // Create new connection
        Connection conn = new Connection();
        conn.tuple = tuple;
        conn.state = ConnectionState.NEW;
        conn.first_seen = Instant.now();
        conn.last_seen = conn.first_seen;

        connections_.put(tuple, conn);
        total_seen_++;

        return conn;
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection direct = connections_.get(tuple);
        if (direct != null) {
            return direct;
        }

        // Try reverse tuple (for bidirectional matching)
        FiveTuple revTuple = tuple.reverse();
        Connection rev = connections_.get(revTuple);
        if (rev != null) {
            return rev;
        }

        return null;
    }

    public void updateConnection(Connection conn, long packet_size, boolean is_outbound) {
        if (conn == null) return;

        conn.last_seen = Instant.now();

        if (is_outbound) {
            conn.packets_out++;
            conn.bytes_out += packet_size;
        } else {
            conn.packets_in++;
            conn.bytes_in += packet_size;
        }
    }

    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;

        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.app_type = app;
            conn.sni = sni;
            conn.state = ConnectionState.CLASSIFIED;
            classified_count_++;
        }
    }

    public void blockConnection(Connection conn) {
        if (conn == null) return;

        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blocked_count_++;
    }

    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections_.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public long cleanupStale(Duration timeout) {
        Instant now = Instant.now();
        long removed = 0;

        Iterator<Map.Entry<FiveTuple, Connection>> it = connections_.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = it.next();
            Connection conn = entry.getValue();

            Duration age = Duration.between(conn.last_seen, now);
            if (age.compareTo(timeout) > 0 || conn.state == ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }

        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections_.values());
    }

    public long getActiveCount() {
        return connections_.size();
    }

    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.active_connections = connections_.size();
        stats.total_connections_seen = total_seen_;
        stats.classified_connections = classified_count_;
        stats.blocked_connections = blocked_count_;
        return stats;
    }

    public void clear() {
        connections_.clear();
    }

    public void forEach(Consumer<Connection> callback) {
        for (Connection conn : connections_.values()) {
            callback.accept(conn);
        }
    }

    private void evictOldest() {
        if (connections_.isEmpty()) return;

        Map.Entry<FiveTuple, Connection> oldest = null;
        for (Map.Entry<FiveTuple, Connection> entry : connections_.entrySet()) {
            if (oldest == null ||
                    entry.getValue().last_seen.isBefore(oldest.getValue().last_seen)) {
                oldest = entry;
            }
        }

        if (oldest != null) {
            connections_.remove(oldest.getKey());
        }
    }
}

// ============================================================================
// GlobalConnectionTable Implementation
// ============================================================================

class GlobalConnectionTable {

    private final List<ConnectionTracker> trackers_;
    private final ReentrantReadWriteLock rwLock_ = new ReentrantReadWriteLock();

    public static class GlobalStats {
        public long total_active_connections;
        public long total_connections_seen;
        public Map<AppType, Long> app_distribution = new HashMap<>();
        public List<Map.Entry<String, Long>> top_domains = new ArrayList<>();
    }

    public GlobalConnectionTable(int num_fps) {
        this.trackers_ = new ArrayList<>(Collections.nCopies(num_fps, null));
    }

    public void registerTracker(int fp_id, ConnectionTracker tracker) {
        rwLock_.writeLock().lock();
        try {
            if (fp_id >= 0 && fp_id < trackers_.size()) {
                trackers_.set(fp_id, tracker);
            }
        } finally {
            rwLock_.writeLock().unlock();
        }
    }

    public GlobalStats getGlobalStats() {
        rwLock_.readLock().lock();
        try {
            GlobalStats stats = new GlobalStats();
            stats.total_active_connections = 0;
            stats.total_connections_seen = 0;

            Map<String, Long> domain_counts = new HashMap<>();

            for (ConnectionTracker tracker : trackers_) {
                if (tracker == null) continue;

                ConnectionTracker.TrackerStats tracker_stats = tracker.getStats();
                stats.total_active_connections += tracker_stats.active_connections;
                stats.total_connections_seen += tracker_stats.total_connections_seen;

                tracker.forEach(conn -> {
                    stats.app_distribution.merge(conn.app_type, 1L, Long::sum);
                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domain_counts.merge(conn.sni, 1L, Long::sum);
                    }
                });
            }

            // Top domains
            List<Map.Entry<String, Long>> domain_vec = new ArrayList<>(domain_counts.entrySet());
            domain_vec.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

            int count = Math.min(domain_vec.size(), 20);
            stats.top_domains = new ArrayList<>(domain_vec.subList(0, count));

            return stats;
        } finally {
            rwLock_.readLock().unlock();
        }
    }

    public String generateReport() {
        GlobalStats stats = getGlobalStats();

        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║               CONNECTION STATISTICS REPORT                    ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        sb.append(String.format("║ Active Connections:     %10d                          ║\n",
                stats.total_active_connections));
        sb.append(String.format("║ Total Connections Seen: %10d                          ║\n",
                stats.total_connections_seen));

        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION BREAKDOWN                      ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        long total = 0;
        for (Long v : stats.app_distribution.values()) {
            total += v;
        }

        List<Map.Entry<AppType, Long>> sorted_apps =
                new ArrayList<>(stats.app_distribution.entrySet());
        sorted_apps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sorted_apps) {
            AppType app = entry.getKey();
            long count = entry.getValue();
            double pct = total > 0 ? (100.0 * count / total) : 0.0;

            sb.append(String.format(
                    "║ %-20s %10d ( %5.1f%%)           ║\n",
                    appTypeToString(app), count, pct));
        }

        if (!stats.top_domains.isEmpty()) {
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║                      TOP DOMAINS                             ║\n");
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");

            for (Map.Entry<String, Long> entry : stats.top_domains) {
                String domain = entry.getKey();
                long count = entry.getValue();

                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }

                sb.append(String.format("║ %-40s %10d           ║\n", domain, count));
            }
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");

        return sb.toString();
    }

    /**
     * Placeholder – implement or replace with a real helper that maps AppType to string.
     */
    private String appTypeToString(AppType appType) {
        return appType.toString();
    }
}


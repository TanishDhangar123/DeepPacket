import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Java translation of {@code FPManager} from {@code fast_path.cpp}.
 *
 * Creates and manages multiple {@link FastPathProcessor} instances.
 */
public class FPManager {

    public static class AggregatedStats {
        public long total_processed;
        public long total_forwarded;
        public long total_dropped;
        public long total_connections;
    }

    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps,
                     RuleManager ruleManager,
                     BiConsumer<PacketJob, PacketAction> outputCallback) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    public void startAll() {
        for (FastPathProcessor fp : fps) {
            fp.start();
        }
    }

    public void stopAll() {
        for (FastPathProcessor fp : fps) {
            fp.stop();
        }
    }

    public FastPathProcessor getFP(int id) {
        return fps.get(id);
    }

    public ThreadSafeQueue<PacketJob> getFPQueue(int id) {
        return fps.get(id).getInputQueue();
    }

    public List<ThreadSafeQueue<PacketJob>> getQueuePtrs() {
        List<ThreadSafeQueue<PacketJob>> list = new ArrayList<>();
        for (FastPathProcessor fp : fps) {
            list.add(fp.getInputQueue());
        }
        return list;
    }

    public int getNumFPs() {
        return fps.size();
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats s = fp.getStats();
            stats.total_processed += s.packets_processed;
            stats.total_forwarded += s.packets_forwarded;
            stats.total_dropped += s.packets_dropped;
            stats.total_connections += s.connections_tracked;
        }
        return stats;
    }

    public String generateClassificationReport() {
        // This mirrors the C++ behavior: aggregate across all FP connection trackers.
        java.util.Map<AppType, Long> appCounts = new java.util.HashMap<>();
        java.util.Map<String, Long> domainCounts = new java.util.HashMap<>();
        long totalClassified = 0;
        long totalUnknown = 0;

        for (FastPathProcessor fp : fps) {
            fp.getConnectionTracker().forEach(conn -> {
                appCounts.merge(conn.app_type, 1L, Long::sum);

                if (conn.app_type == AppType.UNKNOWN) {
                    totalUnknown++;
                } else {
                    totalClassified++;
                }

                if (conn.sni != null && !conn.sni.isEmpty()) {
                    domainCounts.merge(conn.sni, 1L, Long::sum);
                }
            });
        }

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0.0;
        double unknownPct = total > 0 ? (100.0 * totalUnknown / total) : 0.0;

        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        sb.append(String.format("║ Total Connections:    %10d                           ║%n", total));
        sb.append(String.format("║ Classified:           %10d (%5.1f%%)                  ║%n",
                totalClassified, classifiedPct));
        sb.append(String.format("║ Unidentified:         %10d (%5.1f%%)                  ║%n",
                totalUnknown, unknownPct));

        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION DISTRIBUTION                   ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        java.util.List<java.util.Map.Entry<AppType, Long>> sortedApps =
                new java.util.ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (java.util.Map.Entry<AppType, Long> entry : sortedApps) {
            long count = entry.getValue();
            double pct = total > 0 ? (100.0 * count / total) : 0.0;
            int barLen = (int) (pct / 5.0);
            String bar = new String(new char[barLen]).replace('\0', '#');

            sb.append(String.format("║ %-15s %8d %5.1f%% %-20s   ║%n",
                    appTypeToString(entry.getKey()), count, pct, bar));
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    private String appTypeToString(AppType app) {
        return app.toString();
    }
}


import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Java translation of {@code LoadBalancer} and {@code LBManager}
 * from {@code load_balancer.cpp}.
 */
public class LoadBalancer {

    public static class LBStats {
        public long packets_received;
        public long packets_dispatched;
        public List<Long> per_fp_packets;
    }

    private final int lbId;
    private final int fpStartId;
    private final int numFps;

    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10_000);
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;

    private final AtomicLong packetsReceived = new AtomicLong();
    private final AtomicLong packetsDispatched = new AtomicLong();
    private final List<Long> perFpCounts;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public LoadBalancer(int lbId,
                        List<ThreadSafeQueue<PacketJob>> fpQueues,
                        int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.fpQueues = new ArrayList<>(fpQueues);
        this.perFpCounts = new ArrayList<>(fpQueues.size());
        for (int i = 0; i < fpQueues.size(); i++) {
            perFpCounts.add(0L);
        }
    }

    public void start() {
        if (running.get()) {
            return;
        }
        running.set(true);
        thread = new Thread(this::run, "lb-thread-" + lbId);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP"
                + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
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
        System.out.println("[LB" + lbId + "] Stopped");
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public boolean isRunning() {
        return running.get();
    }

    public int getId() {
        return lbId;
    }

    private void run() {
        while (running.get()) {
            PacketJob job = inputQueue.popWithTimeout(100);
            if (job == null) {
                continue;
            }

            packetsReceived.incrementAndGet();

            int fpIndex = selectFP(job.tuple);
            fpQueues.get(fpIndex).push(job);

            packetsDispatched.incrementAndGet();
            perFpCounts.set(fpIndex, perFpCounts.get(fpIndex) + 1);
        }
    }

    private int selectFP(FiveTuple tuple) {
        long hash = FiveTupleHash.hash(tuple);
        return (int) (hash % numFps);
    }

    public LBStats getStats() {
        LBStats stats = new LBStats();
        stats.packets_received = packetsReceived.get();
        stats.packets_dispatched = packetsDispatched.get();
        stats.per_fp_packets = new ArrayList<>(perFpCounts);
        return stats;
    }

    // -------------------------------------------------------------------------
    // LBManager
    // -------------------------------------------------------------------------

    public static class LBManager {

        public static class AggregatedStats {
            public long total_received;
            public long total_dispatched;
        }

        private final List<LoadBalancer> lbs = new ArrayList<>();
        private final int fpsPerLb;

        public LBManager(int numLbs,
                         int fpsPerLb,
                         List<ThreadSafeQueue<PacketJob>> fpQueues) {
            this.fpsPerLb = fpsPerLb;

            for (int lbId = 0; lbId < numLbs; lbId++) {
                List<ThreadSafeQueue<PacketJob>> lbFpQueues = new ArrayList<>();
                int fpStart = lbId * fpsPerLb;
                for (int i = 0; i < fpsPerLb; i++) {
                    lbFpQueues.add(fpQueues.get(fpStart + i));
                }
                lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
            }

            System.out.println("[LBManager] Created " + numLbs
                    + " load balancers, " + fpsPerLb + " FPs each");
        }

        public void startAll() {
            for (LoadBalancer lb : lbs) {
                lb.start();
            }
        }

        public void stopAll() {
            for (LoadBalancer lb : lbs) {
                lb.stop();
            }
        }

        public LoadBalancer getLBForPacket(FiveTuple tuple) {
            long hash = FiveTupleHash.hash(tuple);
            int lbIndex = (int) (hash % lbs.size());
            return lbs.get(lbIndex);
        }

        public LoadBalancer getLB(int id) {
            return lbs.get(id);
        }

        public int getNumLBs() {
            return lbs.size();
        }

        public AggregatedStats getAggregatedStats() {
            AggregatedStats stats = new AggregatedStats();
            for (LoadBalancer lb : lbs) {
                LBStats s = lb.getStats();
                stats.total_received += s.packets_received;
                stats.total_dispatched += s.packets_dispatched;
            }
            return stats;
        }
    }
}


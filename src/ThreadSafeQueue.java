import java.util.ArrayDeque;
import java.util.Queue;

/**
 * Java equivalent of C++ {@code ThreadSafeQueue<T>} used for
 * Reader → LoadBalancer → FastPath communication.
 */
public class ThreadSafeQueue<T> {

    private final Queue<T> queue = new ArrayDeque<>();
    private final int maxSize;
    private boolean shutdown = false;

    public ThreadSafeQueue() {
        this(10_000);
    }

    public ThreadSafeQueue(int maxSize) {
        this.maxSize = maxSize;
    }

    /**
     * Push item to queue (blocks if full, returns immediately after shutdown).
     */
    public void push(T item) {
        synchronized (queue) {
            while (queue.size() >= maxSize && !shutdown) {
                try {
                    queue.wait();
                } catch (InterruptedException ignored) {
                }
            }
            if (shutdown) {
                return;
            }
            queue.add(item);
            queue.notifyAll();
        }
    }

    /**
     * Try to push without blocking.
     *
     * @return true if the item was enqueued, false if full or shutdown.
     */
    public boolean tryPush(T item) {
        synchronized (queue) {
            if (queue.size() >= maxSize || shutdown) {
                return false;
            }
            queue.add(item);
            queue.notifyAll();
            return true;
        }
    }

    /**
     * Pop item from queue (blocks until item available or shutdown).
     */
    public T pop() {
        synchronized (queue) {
            while (queue.isEmpty() && !shutdown) {
                try {
                    queue.wait();
                } catch (InterruptedException ignored) {
                }
            }
            if (queue.isEmpty()) {
                return null;
            }
            T item = queue.remove();
            queue.notifyAll();
            return item;
        }
    }

    /**
     * Pop with timeout (milliseconds). Returns null on timeout or shutdown.
     */
    public T popWithTimeout(long timeoutMillis) {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        synchronized (queue) {
            while (queue.isEmpty() && !shutdown) {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) {
                    return null;
                }
                try {
                    queue.wait(remaining);
                } catch (InterruptedException ignored) {
                }
            }
            if (queue.isEmpty()) {
                return null;
            }
            T item = queue.remove();
            queue.notifyAll();
            return item;
        }
    }

    public boolean empty() {
        synchronized (queue) {
            return queue.isEmpty();
        }
    }

    public int size() {
        synchronized (queue) {
            return queue.size();
        }
    }

    /**
     * Signal shutdown (wake up all waiting threads and prevent new enqueues).
     */
    public void shutdown() {
        synchronized (queue) {
            shutdown = true;
            queue.notifyAll();
        }
    }

    public boolean isShutdown() {
        synchronized (queue) {
            return shutdown;
        }
    }
}


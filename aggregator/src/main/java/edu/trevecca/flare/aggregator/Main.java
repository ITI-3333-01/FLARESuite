package edu.trevecca.flare.aggregator;

import static edu.trevecca.flare.core.logging.Logging.getLogger;

import edu.trevecca.flare.core.redis.Redis;
import java.util.concurrent.Callable;
import java.util.logging.Logger;
import picocli.CommandLine;
import picocli.CommandLine.Option;

public class Main implements Callable<Void> {

    /**
     * Console logging
     */
    public static final Logger logger = getLogger("Main");
    /**
     * Set to false by a shutdown handler which ends the main program loop.
     */
    private volatile boolean doLoop = true;
    /**
     * Redis host
     */
    @Option(names = "-rh, --redis-host", defaultValue = "localhost",
            description = "Hostname of the redis server used for cross-node communication") private String redisHost;
    /**
     * Redis port
     */
    @Option(names = "-rp, --redis-port", defaultValue = "6379",
            description = "Port of the redis server used for cross-node communication") private int redisPort;
    /**
     * Redis
     */
    public static Redis redis;

    public static void main(String[] args) throws Exception {
        // Parse args (see above)
        // If everything works out OK, the call() method under this will be executed.
        CommandLine.call(new Main(), args);
    }

    @Override
    public Void call() throws Exception {
        // Run this when the process is terminated.
        Runtime.getRuntime().addShutdownHook(new Thread(this::finish));

        redis = Redis.builder(redisHost, redisPort).reconnect(true).build();
        redis.enable();
        redis.register(new PacketRedisHandler());

        while (doLoop) {
            Thread.sleep(1000);
        }

        return null;
    }

    /**
     * Called when the JVM is shutting down.
     */
    private void finish() {
        this.doLoop = false;
    }
}

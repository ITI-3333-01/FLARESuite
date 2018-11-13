package edu.trevecca.flare.aggregator;

import static edu.trevecca.flare.core.logging.Logging.getLogger;

import edu.trevecca.flare.core.redis.Redis;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
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
    private boolean doLoop = true;
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
    /**
     * Output file path
     */
    @Option(names = {
        "-o",
        "--out"
    }, description = "File to print data to.")
    private String outPath;
    private File outFile;

    public static void main(String[] args) throws Exception {
        // Parse args (see above)
        // If everything works out OK, the call() method under this will be executed.
        CommandLine.call(new Main(), args);
    }

    @Override
    public Void call() throws Exception {
        // Run this when the process is terminated.
        Runtime.getRuntime().addShutdownHook(new Thread(this::finish));

        makeFile();

        redis = Redis.builder(redisHost, redisPort).reconnect(true).build();
        redis.enable();
        redis.register(new PacketRedisHandler(outFile));

        while (doLoop) {

        }

        return null;
    }

    private void makeFile() {
        File file = new File(outPath);
        if (file.exists()) {
            if (file.isDirectory()) {
                logger.severe("Output file cannot be a directory!");
                System.exit(1);
            }
            else {
                logger.warning("Output file already exists, clearing...");
                try {
                    PrintWriter writer = new PrintWriter(file);
                    writer.close();
                }
                catch (FileNotFoundException ignored) {
                } // Not Possible
            }
        }
        outFile = file;
    }

    /**
     * Called when the JVM is shutting down.
     */
    private void finish() {
        this.doLoop = false;
    }
}

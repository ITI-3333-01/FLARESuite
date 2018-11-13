package edu.trevecca.flare.daemon;

import static edu.trevecca.flare.core.logging.Logging.getLogger;

import java.util.concurrent.Callable;
import java.util.logging.Logger;
import picocli.CommandLine;

public class Main implements Callable<Void> {

    /**
     * Console logging
     */
    public static final Logger logger = getLogger("Main");
    /**
     * Set to false by a shutdown handler which ends the main program loop.
     */
    private boolean doLoop = true;

    public static void main(String[] args) throws Exception {
        // Parse args (see above)
        // If everything works out OK, the call() method under this will be executed.
        CommandLine.call(new Main(), args);
    }

    @Override
    public Void call() throws Exception {

        // Run this when the process is terminated.
        Runtime.getRuntime().addShutdownHook(new Thread(this::finish));

        while (doLoop) {

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

package edu.trevecca.flare.core.logging;

import java.util.logging.ConsoleHandler;
import java.util.logging.Logger;

public class Logging {

    /**
     * Get a logger by name, and add in a {@link CustomFormatter} to make logging output more friendly.
     *
     * @param name of the logger
     * @return a logger matching the requested name
     */
    public static Logger getLogger(String name) {
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new CustomFormatter());
        Logger logger = Logger.getLogger(name);
        logger.addHandler(handler);
        logger.setUseParentHandlers(false);
        return logger;
    }
}

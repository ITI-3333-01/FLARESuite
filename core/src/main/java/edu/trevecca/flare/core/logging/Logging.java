package edu.trevecca.flare.core.logging;

import java.util.logging.ConsoleHandler;
import java.util.logging.Logger;

public class Logging {

    public Logging() {
    }

    public static Logger getLogger(String name) {
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new CustomFormatter());
        Logger logger = Logger.getLogger(name);
        logger.addHandler(handler);
        logger.setUseParentHandlers(false);
        return logger;
    }
}

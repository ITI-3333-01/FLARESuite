package edu.trevecca.flare.collector;

import edu.trevecca.flare.core.transfer.PackerDumpRedisMessage;
import java.net.Inet4Address;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

public class StatsUtils {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yy-MM-dd-HH-mm-ss");

    public static void dumpStats(Instant start, Map<Inet4Address, AtomicInteger> ipTraffic, int statsWindow, Logger logger) {
        Main.redis.publish(new PackerDumpRedisMessage(start, ipTraffic, statsWindow));
    }
}

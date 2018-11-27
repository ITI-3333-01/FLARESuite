package edu.trevecca.flare.collector;

import edu.trevecca.flare.core.transfer.PackerDumpRedisMessage;
import java.net.Inet4Address;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

public class StatsUtils {

    public static void dumpStats(Instant start, Map<Inet4Address, AtomicInteger> outboundTraffic,
                                 Map<Inet4Address, AtomicInteger> inboundTraffic, int statsWindow, Logger logger) {
        Main.redis.publish(new PackerDumpRedisMessage(start, outboundTraffic, inboundTraffic, statsWindow));
    }
}

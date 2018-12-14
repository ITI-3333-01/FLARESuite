package edu.trevecca.flare.collector;

import edu.trevecca.flare.core.transfer.PackerDumpRedisMessage;
import java.net.Inet4Address;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class StatsUtils {

    /**
     * Dump statistics to redis.
     *
     * @param start           when the packet dump started
     * @param outboundTraffic traffic going out of the network
     * @param inboundTraffic  traffic coming in to the network
     * @param statsWindow     time between dumps
     */
    public static void dumpStats(Instant start, Map<Inet4Address, AtomicInteger> outboundTraffic,
                                 Map<Inet4Address, AtomicInteger> inboundTraffic, int statsWindow, int badNets) {
        Main.redis.publish(new PackerDumpRedisMessage(start, outboundTraffic, inboundTraffic, statsWindow, badNets));
    }
}

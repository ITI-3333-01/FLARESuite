package edu.trevecca.flare.collector;

import com.google.common.collect.Multimap;
import edu.trevecca.flare.core.transfer.PacketDumpRedisMessage;
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
     * @param dnsResolutions  map of domain -> resolved IPs during the time period
     * @param statsWindow     time between dumps
     */
    public static void dumpStats(Instant start, Map<Inet4Address, AtomicInteger> outboundTraffic,
                                 Map<Inet4Address, AtomicInteger> inboundTraffic, Multimap<String, Inet4Address> dnsResolutions,
                                 int statsWindow, int badNets) {
        Main.redis
            .publish(new PacketDumpRedisMessage(start, outboundTraffic, inboundTraffic, dnsResolutions, statsWindow, badNets));
    }
}

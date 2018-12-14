package edu.trevecca.flare.core.transfer;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import edu.trevecca.flare.core.redis.RedisMessage;
import java.net.Inet4Address;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class PackerDumpRedisMessage implements RedisMessage {

    private final Instant start;
    private final Map<Inet4Address, AtomicInteger> outboundTraffic;
    private final Map<Inet4Address, AtomicInteger> inboundTraffic;
    private final int statsWindow;
    private final int badNets;

    /**
     * Constructor.
     *
     * @param start           when the packet dump started
     * @param outboundTraffic traffic going out of the network
     * @param inboundTraffic  traffic coming in to the network
     * @param statsWindow     time between dumps
     * @param badNets         number of packets received from net-masks outside of the capture range
     */
    public PackerDumpRedisMessage(Instant start,
                                  Map<Inet4Address, AtomicInteger> outboundTraffic,
                                  Map<Inet4Address, AtomicInteger> inboundTraffic, int statsWindow, int badNets) {
        this.start = start;
        this.outboundTraffic = outboundTraffic;
        this.inboundTraffic = inboundTraffic;
        this.statsWindow = statsWindow;
        this.badNets = badNets;
    }

    @Override public String channel() {
        return "packet-data";
    }

    @Override public JsonObject write() {
        JsonObject object = new JsonObject();

        object.addProperty("start", this.start.getEpochSecond());
        object.addProperty("window", this.statsWindow);
        object.addProperty("bad-nets", this.badNets);

        object.add("outbound", writeData(this.outboundTraffic));
        object.add("inbound", writeData(this.inboundTraffic));

        return object;
    }

    private JsonArray writeData(Map<Inet4Address, AtomicInteger> data) {
        JsonArray packetData = new JsonArray();
        Map<Inet4Address, AtomicInteger> traffic = data.entrySet()
                                                       .stream()
                                                       .sorted((a, b) -> Integer.compare(b.getValue().get(), a.getValue().get()))
                                                       .collect(
                                                           Collectors
                                                               .toMap(
                                                                   Map.Entry::getKey, Map.Entry::getValue, (e1, e2) -> e1,
                                                                   LinkedHashMap::new
                                                                     ));

        double total = traffic.values().stream().mapToInt(AtomicInteger::get).sum();
        traffic.forEach((k, v) -> {
            JsonObject packet = new JsonObject();
            packet.addProperty("host", k.getHostAddress());
            packet.addProperty("total", v.get());
            packet.addProperty("percent", v.get() / total);
            packetData.add(packet);
        });

        return packetData;
    }
}

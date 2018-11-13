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
    private final Map<Inet4Address, AtomicInteger> ipTraffic;
    private final int statsWindow;

    public PackerDumpRedisMessage(Instant start,
                                  Map<Inet4Address, AtomicInteger> ipTraffic, int statsWindow) {
        this.start = start;
        this.ipTraffic = ipTraffic;
        this.statsWindow = statsWindow;
    }

    @Override public String channel() {
        return "packet-data";
    }

    @Override public JsonObject write() {
        JsonObject object = new JsonObject();

        object.addProperty("start", this.start.getEpochSecond());
        object.addProperty("window", this.statsWindow);
        JsonArray packetData = new JsonArray();
        Map<Inet4Address, AtomicInteger> traffic = ipTraffic.entrySet()
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

        object.add("data", packetData);

        return object;
    }
}

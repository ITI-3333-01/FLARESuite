package edu.trevecca.flare.core.transfer;

import com.google.common.collect.Multimap;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import edu.trevecca.flare.core.redis.RedisMessage;
import java.net.Inet4Address;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class PackerDumpRedisMessage implements RedisMessage {

    private final Instant start;
    private final Map<Inet4Address, AtomicInteger> outboundTraffic;
    private final Map<Inet4Address, AtomicInteger> inboundTraffic;
    private final Multimap<String, Inet4Address> dnsResolutions;
    private final int statsWindow;
    private final int badNets;

    /**
     * Constructor.
     *
     * @param start           when the packet dump started
     * @param outboundTraffic traffic going out of the network
     * @param inboundTraffic  traffic coming in to the network
     * @param dnsResolutions  map of domain -> resolved IPs during the time period
     * @param statsWindow     time between dumps
     * @param badNets         number of packets received from net-masks outside of the capture range
     */
    public PackerDumpRedisMessage(Instant start,
                                  Map<Inet4Address, AtomicInteger> outboundTraffic,
                                  Map<Inet4Address, AtomicInteger> inboundTraffic,
                                  Multimap<String, Inet4Address> dnsResolutions,
                                  int statsWindow, int badNets) {
        this.start = start;
        this.outboundTraffic = outboundTraffic;
        this.inboundTraffic = inboundTraffic;
        this.dnsResolutions = dnsResolutions;
        this.statsWindow = statsWindow;
        this.badNets = badNets;
    }

    @Override public String channel() {
        return "packet-data";
    }

    @Override public JsonObject write() {
        JsonObject object = new JsonObject();

        // Generic Info
        object.addProperty("start", this.start.toEpochMilli());
        object.addProperty("window", this.statsWindow);
        object.addProperty("bad-nets", this.badNets);

        // Traffic
        object.add("outbound", writeData(this.outboundTraffic));
        object.add("inbound", writeData(this.inboundTraffic));

        // DNS
        object.add("dns", writeDNS());

        return object;
    }

    private JsonArray writeDNS() {
        JsonArray dns = new JsonArray();

        for (int lol = 0; lol < 5; lol++) {
            for (String domain : dnsResolutions.keys()) {
                JsonObject resolution = new JsonObject();
                resolution.addProperty("domain", domain);
                JsonArray ips = new JsonArray();
                new HashSet<>(dnsResolutions.get(domain)).forEach(i -> ips.add(i.getHostAddress()));
                resolution.add("ips", ips);
                dns.add(resolution);
            }
        }

        return dns;
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
        for (int lol = 0; lol < 5; lol++) {
            traffic.forEach((k, v) -> {
                JsonObject packet = new JsonObject();
                packet.addProperty("host", k.getHostAddress());
                packet.addProperty("total", v.get());
                packet.addProperty("percent", (double) v.get() / total);
                packetData.add(packet);
            });
        }

        return packetData;
    }
}

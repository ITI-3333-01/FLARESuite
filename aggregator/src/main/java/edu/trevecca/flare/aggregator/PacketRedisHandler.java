package edu.trevecca.flare.aggregator;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.net.InternetDomainName;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import edu.trevecca.flare.core.redis.RedisHandler;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map.Entry;

/**
 * Listens for {@link edu.trevecca.flare.core.transfer.PackerDumpRedisMessage} and handles them.
 */
public class PacketRedisHandler implements RedisHandler {

    private final String DUMP_INSERT = "INSERT into dumps (time, error, total) VALUES (?, ?, ?)";
    private final String DNS_INSERT = "INSERT into dns_dump (domain, ip_address, timestamp) VALUES (?, ?, ?, ?)";
    private final String INFO_INSERT =
        "INSERT into dump_info (ip_address, direction, ip_count, dns, time, ratio, dns_root) VALUES (?, ?, ?, ?, ?, ?, ?)";

    @Override public String[] channels() {
        return new String[]{"packet-data"};
    }

    @Override public void handle(JsonObject json) {
        try {
            // TODO: Probably shouldn't hardcode this
            try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost/flare?" +
                                                              "user=root&password=BLAZE")) {
                PreparedStatement dumpInsert = con.prepareStatement(DUMP_INSERT);
                PreparedStatement infoInsert = con.prepareStatement(INFO_INSERT);
                PreparedStatement dnsInsert = con.prepareStatement(DNS_INSERT);

                Timestamp time = new Timestamp(json.get("start").getAsLong());

                // Log window information
                int size = json.get("outbound").getAsJsonArray().size() + json.get("inbound").getAsJsonArray().size();
                dumpInsert.setTimestamp(1, time);
                dumpInsert.setInt(2, json.get("bad-nets").getAsInt());
                dumpInsert.setInt(3, size);
                dumpInsert.execute();

                // Resolve DNS early so it can be used below
                Multimap<String, String> dns = HashMultimap.create();
                for (JsonElement dnsEl : json.get("dns").getAsJsonArray()) {
                    JsonObject data = dnsEl.getAsJsonObject();
                    String domain = data.get("domain").getAsString();
                    for (JsonElement ip : data.get("ips").getAsJsonArray()) {
                        dns.put(domain, ip.getAsString());
                    }
                }

                // Save traffic
                for (JsonElement outbound : json.get("outbound").getAsJsonArray()) {
                    addInfoBatch(infoInsert, outbound.getAsJsonObject(), false, time, dns);
                }
                for (JsonElement inbound : json.get("inbound").getAsJsonArray()) {
                    addInfoBatch(infoInsert, inbound.getAsJsonObject(), true, time, dns);
                }

                // Record traffic
                infoInsert.executeLargeBatch();

                // Record DNS
                addDNS(dnsInsert, dns, time);
                dnsInsert.executeLargeBatch();
            }
            /*
            try (PrintWriter writer = new PrintWriter(out)) {
                json.addProperty("files-recorded", this.received.incrementAndGet());
                writer.println(json);
            }
            */
        }
        catch (Exception e) {
            Main.logger.severe("Failed to handle packet data!");
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void addDNS(PreparedStatement statement, Multimap<String, String> data, Timestamp time) throws Exception {
        for (Entry<String, Collection<String>> entry : HashMultimap.create(data).asMap().entrySet()) {
            data.get(entry.getKey()).removeIf(ip -> data.values().stream().filter(s -> s.equals(ip)).count() > 1);
        }
        for (Entry<String, Collection<String>> entry : data.asMap().entrySet()) {
            for (String ip : new HashSet<>(entry.getValue())) {
                statement.setString(1, entry.getKey());
                statement.setString(2, ip);
                statement.setTimestamp(3, time);
                statement.addBatch();
            }
        }
    }

    private void addInfoBatch(PreparedStatement infoStatement, JsonObject data, boolean in, Timestamp time,
                              Multimap<String, String> dns) throws Exception {
        String direction = in ? "inbound" : "outbound";
        infoStatement.setString(1, data.get("host").getAsString());
        infoStatement.setString(2, direction);
        infoStatement.setInt(3, data.get("total").getAsInt());

        String host = getHost(data.get("host").getAsString(), dns);
        infoStatement.setString(4, host);

        infoStatement.setTimestamp(5, time);
        infoStatement.setFloat(6, data.get("percent").getAsFloat());
        infoStatement.setString(7, InternetDomainName.from(host).topPrivateDomain().toString());

        infoStatement.addBatch();
    }

    private String getHost(String address, Multimap<String, String> dnsResolutions) {
        if (!dnsResolutions.containsValue(address)) {
            Main.logger.severe("Failed to get DNS resolution for " + address);
            return address;
        }
        else {
            for (Entry<String, String> entry : dnsResolutions.entries()) {
                if (entry.getValue().equals(address)) {
                    return entry.getKey();
                }
            }
        }
        throw new IllegalStateException("Failed to find key in map!");
    }
}

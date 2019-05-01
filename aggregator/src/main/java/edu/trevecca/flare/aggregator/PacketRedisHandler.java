package edu.trevecca.flare.aggregator;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.net.InternetDomainName;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import edu.trevecca.flare.core.redis.RedisHandler;
import edu.trevecca.flare.core.transfer.PacketDumpRedisMessage;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;

/**
 * Listens for {@link PacketDumpRedisMessage} and handles them.
 */
public class PacketRedisHandler implements RedisHandler {

    private final String DNS_LOOKUP = "SELECT domain from dns_dump where ip_address = (?) ORDER BY time DESC LIMIT 1";
    private final String DUMP_INSERT = "INSERT into dumps (time, error, total) VALUES (?, ?, ?)";
    private final String DNS_INSERT = "INSERT into dns_dump (domain, ip_address, time) VALUES (?, ?, ?)";
    private final String DNS_UPDATE = "UPDATE dns_dump SET time = (?) WHERE ip_address = (?) ORDER BY time DESC LIMIT 1";
    private final String DNS_CHECK = "SELECT domain FROM dns_dump WHERE ip_address = (?) ORDER BY time DESC LIMIT 1";
    private final String INFO_INSERT =
        "INSERT into dump_info (ip_address, direction, ip_count, dns, time, ratio, dns_root) VALUES (?, ?, ?, ?, ?, ?, ?)";

    @Override public String[] channels() {
        return new String[]{"packet-data"};
    }

    @Override public void handle(JsonObject json) {
        try {
            // TODO: Probably shouldn't hardcode this
            try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost/flare?" +
                                                              "user=flare&password=Flare-3333")) {
                con.setAutoCommit(false);
                PreparedStatement dumpInsert = con.prepareStatement(DUMP_INSERT);
                PreparedStatement infoInsert = con.prepareStatement(INFO_INSERT);
                PreparedStatement dnsInsert = con.prepareStatement(DNS_INSERT);
                PreparedStatement dnsUpdate = con.prepareStatement(DNS_UPDATE);

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

                PreparedStatement dnsSearch = con.prepareStatement(DNS_LOOKUP);
                PreparedStatement dnsCheck = con.prepareStatement(DNS_CHECK);

                // Save traffic
                for (JsonElement outbound : json.get("outbound").getAsJsonArray()) {
                    addInfoBatch(infoInsert, outbound.getAsJsonObject(), false, time, dns, dnsSearch);
                }
                for (JsonElement inbound : json.get("inbound").getAsJsonArray()) {
                    addInfoBatch(infoInsert, inbound.getAsJsonObject(), true, time, dns, dnsSearch);
                }

                // Record traffic
                infoInsert.executeBatch();

                // Record DNS
                addDNS(dnsInsert, dnsUpdate, dns, time, dnsCheck);
                Main.logger.info(Arrays.stream(dnsInsert.executeBatch()).sum() + " DNS entries inserted");
                Main.logger.info(Arrays.stream(dnsUpdate.executeBatch()).sum() + " DNS entries updated");
                Main.logger.info(size + " info entries inserted");
                con.commit();
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
        System.gc();
    }

    private void addDNS(PreparedStatement dnsInsert, PreparedStatement dnsUpdate,
        Multimap<String, String> data, Timestamp time, PreparedStatement dnsCheck) throws Exception {
        for (Entry<String, Collection<String>> entry : HashMultimap.create(data).asMap().entrySet()) {
            data.get(entry.getKey()).removeIf(ip -> data.values().stream().filter(s -> s.equals(ip)).count() > 1);
        }
        for (Entry<String, Collection<String>> entry : data.asMap().entrySet()) {
            for (String ip : new HashSet<>(entry.getValue())) {
                dnsCheck.setString(1, ip);
                ResultSet search = dnsCheck.executeQuery();
                if (search.next() && search.getString(1).equalsIgnoreCase(entry.getKey())) {
                    dnsUpdate.setTimestamp(1, time);
                    dnsUpdate.setString(2, ip);
                    dnsUpdate.addBatch();
                    continue;
                }
                dnsInsert.setString(1, entry.getKey());
                dnsInsert.setString(2, ip);
                dnsInsert.setTimestamp(3, time);
                dnsInsert.addBatch();
            }
        }
    }

    private void addInfoBatch(PreparedStatement infoStatement, JsonObject data, boolean in, Timestamp time,
                              Multimap<String, String> dns, PreparedStatement dnsSearch) throws Exception {
        infoStatement.setString(1, data.get("host").getAsString());
        infoStatement.setInt(2, in ? 1 : 0);
        infoStatement.setInt(3, data.get("total").getAsInt());

        String host = getHost(data.get("host").getAsString(), dns, dnsSearch);
        infoStatement.setString(4, host);

        infoStatement.setTimestamp(5, time);
        infoStatement.setFloat(6, data.get("percent").getAsFloat());
        try {
            InternetDomainName rootDomain = InternetDomainName.from(host);
            List<String> root = rootDomain.parts().subList(rootDomain.parts().size() - 2, rootDomain.parts().size());
            String actualRoot = root.get(0) + "." + root.get(1);
            infoStatement.setString(7, actualRoot);
        } catch (Exception ignored) {
            infoStatement.setString(7, host);
        }

        infoStatement.addBatch();
    }

    private String getHost(String address, Multimap<String, String> dnsResolutions, PreparedStatement dnsSearch) {
        if (!dnsResolutions.containsValue(address)) {
            try {
                dnsSearch.setString(1, address);
                ResultSet res = dnsSearch.executeQuery();
                if (res.next()) {
                    return res.getString(1);
                }
            }
            catch (SQLException e) {
                e.printStackTrace();
            }
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

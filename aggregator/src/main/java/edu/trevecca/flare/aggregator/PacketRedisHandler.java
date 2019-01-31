package edu.trevecca.flare.aggregator;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import edu.trevecca.flare.core.redis.RedisHandler;
import java.io.File;
import java.net.InetAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Listens for {@link edu.trevecca.flare.core.transfer.PackerDumpRedisMessage} and handles them.
 */
public class PacketRedisHandler implements RedisHandler {

    private final String DUMP_INSERT = "INSERT into dumps (time, error, total) VALUES (?, ?, ?)";
    private final String INFO_INSERT = "INSERT into dump_info (ip_address, direction, ip_count, dns, time, ratio) VALUES (?, ?, ?, ?, ?, ?)";

    private final File out;
    private final AtomicInteger received = new AtomicInteger();

    PacketRedisHandler(File out) {
        this.out = out;
    }

    @Override public String[] channels() {
        return new String[]{"packet-data"};
    }

    @Override public void handle(JsonObject json) {
        try {
            try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost/flare?" +
                    "user=root&password=BLAZE")) {
                PreparedStatement dumpInsert = con.prepareStatement(DUMP_INSERT);
                PreparedStatement infoInsert = con.prepareStatement(INFO_INSERT);

                Timestamp time = new Timestamp(json.get("start").getAsLong());

                int size = json.get("outbound").getAsJsonArray().size() + json.get("inbound").getAsJsonArray().size();
                dumpInsert.setTimestamp(1, time);
                dumpInsert.setInt(2, json.get("bad-nets").getAsInt());
                dumpInsert.setInt(3, size);

                dumpInsert.execute();

                for (JsonElement outbound : json.get("outbound").getAsJsonArray()) {
                    addInfoBatch(infoInsert, outbound.getAsJsonObject(), false, time);
                }

                for (JsonElement inbound : json.get("inbound").getAsJsonArray()) {
                    addInfoBatch(infoInsert, inbound.getAsJsonObject(), true, time);
                }

                infoInsert.executeLargeBatch();
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

    private void addInfoBatch(PreparedStatement infoStatement, JsonObject data, boolean in, Timestamp time) throws Exception {
        String direction = in ? "inbound" : "outbound";
        infoStatement.setString(1, data.get("host").getAsString());
        infoStatement.setString(2, direction);
        infoStatement.setInt(3, data.get("total").getAsInt());

        InetAddress addr = InetAddress.getByName(data.get("host").getAsString());
        infoStatement.setString(4, addr.getHostName());

        infoStatement.setTimestamp(5, time);
        infoStatement.setFloat(6, data.get("percent").getAsFloat());

        infoStatement.addBatch();
    }
}

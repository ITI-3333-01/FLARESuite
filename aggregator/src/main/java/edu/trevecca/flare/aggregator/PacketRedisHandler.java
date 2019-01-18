package edu.trevecca.flare.aggregator;

import com.google.gson.JsonObject;
import edu.trevecca.flare.core.redis.RedisHandler;
import java.io.File;
import java.io.PrintWriter;
import java.sql.*;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Listens for {@link edu.trevecca.flare.core.transfer.PackerDumpRedisMessage} and handles them.
 */
public class PacketRedisHandler implements RedisHandler {

    private final String DUMP_INSERT = "INSERT into dumps (time, error, total) VALUES (?, ?, ?)";

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
                PreparedStatement insert = con.prepareStatement(DUMP_INSERT);

                int size = json.get("outbound").getAsJsonArray().size() + json.get("inbound").getAsJsonArray().size();
                insert.setTimestamp(1, new Timestamp(json.get("start").getAsLong()));
                insert.setInt(2, json.get("bad-nets").getAsInt());
                insert.setInt(3, size);

                insert.execute();
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
}

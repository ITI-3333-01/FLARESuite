package edu.trevecca.flare.aggregator;

import com.google.gson.JsonObject;
import edu.trevecca.flare.core.redis.RedisHandler;
import java.io.File;
import java.io.PrintWriter;
import java.util.Date;

public class PacketRedisHandler implements RedisHandler {

    private final File out;

    public PacketRedisHandler(File out) {
        this.out = out;
    }

    @Override public String[] channels() {
        return new String[]{"packet-data"};
    }

    @Override public void handle(JsonObject json) {
        try {
            try (PrintWriter writer = new PrintWriter(out)) {
                writer.println("# Packet data output file v1.0.0.");
                writer.println("# File written on " + new Date() + ".");
                writer.println("# Data Format: host | total | percent");
                writer.println();
                writer.println("Collection start: " + json.get("start").getAsLong());
                writer.println("Collection window: " + json.get("window").getAsInt());
                writer.println("data: ");
                json.get("data").getAsJsonArray().forEach(d -> {
                    JsonObject dataElement = d.getAsJsonObject();
                    String host = dataElement.get("host").getAsString();
                    int total = dataElement.get("total").getAsInt();
                    double percent = dataElement.get("percent").getAsDouble();
                    writer.println("  " + host + " | " + total + " | " + percent);
                });
            }
        }
        catch (Exception e) {
            Main.logger.severe("Failed to handle packet data!");
            e.printStackTrace();
            System.exit(1);
        }
    }
}

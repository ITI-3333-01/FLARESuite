package edu.trevecca.flare.aggregator;

import com.google.gson.JsonObject;
import edu.trevecca.flare.core.redis.RedisHandler;
import java.io.File;
import java.io.PrintWriter;

/**
 * Listens for {@link edu.trevecca.flare.core.transfer.PackerDumpRedisMessage} and handles them.
 */
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
                writer.println(json);
            }
        }
        catch (Exception e) {
            Main.logger.severe("Failed to handle packet data!");
            e.printStackTrace();
            System.exit(1);
        }
    }
}

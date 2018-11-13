package edu.trevecca.flare.core.redis;

import com.google.gson.JsonObject;

public interface RedisHandler {

    String[] channels();

    default boolean matches(String channel) {
        String[] var2 = this.channels();
        int var3 = var2.length;

        for (int var4 = 0; var4 < var3; ++var4) {
            String check = var2[var4];
            if (check.equals(channel)) {
                return true;
            }
        }

        return false;
    }

    void handle(JsonObject var1);
}

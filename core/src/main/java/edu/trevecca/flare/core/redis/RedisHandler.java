package edu.trevecca.flare.core.redis;

import com.google.gson.JsonObject;

public interface RedisHandler {

    String[] channels();

    default boolean matches(String channel) {
        String[] matchers = this.channels();

        for (String check : matchers) {
            if (check.equals(channel)) {
                return true;
            }
        }

        return false;
    }

    void handle(JsonObject object);
}

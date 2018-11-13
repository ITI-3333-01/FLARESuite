package edu.trevecca.flare.core.redis;

import com.google.gson.JsonObject;

public interface RedisMessage {

    String channel();

    JsonObject write();
}

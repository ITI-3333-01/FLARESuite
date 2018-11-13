package edu.trevecca.flare.core.redis;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.lettuce.core.pubsub.RedisPubSubListener;

public class RedisListener implements RedisPubSubListener<String, String> {

    private static final JsonParser parser = new JsonParser();
    private final Redis redis;

    RedisListener(Redis redis) {
        this.redis = redis;
    }

    public void message(String channel, String body) {
        JsonObject json = parser.parse(body).getAsJsonObject();
        this.redis.handlers().stream().filter((handler) -> handler.matches(channel)).forEach((handler) -> handler.handle(json));
    }

    public void message(String s, String k1, String s2) {
    }

    public void subscribed(String s, long l) {
    }

    public void psubscribed(String s, long l) {
    }

    public void unsubscribed(String s, long l) {
    }

    public void punsubscribed(String s, long l) {
    }
}

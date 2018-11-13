package edu.trevecca.flare.core.redis;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import io.lettuce.core.pubsub.StatefulRedisPubSubConnection;
import io.lettuce.core.pubsub.api.sync.RedisPubSubCommands;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;

public class Redis {

    private final RedisClient client;
    private Optional<RedisCommands<String, String>> connection;
    private Optional<RedisPubSubCommands<String, String>> pubSubCommands;
    private final List<RedisHandler> handlers;

    public Redis(RedisURI uri, ClientOptions options) {
        this.client = RedisClient.create(uri);
        this.client.setOptions(options);
        this.connection = Optional.empty();
        this.handlers = new ArrayList();
    }

    public static Redis.Builder builder(String host, int port) {
        return new Redis.Builder(host, port);
    }

    public boolean hset(String name, String key, String value) {
        return ((RedisCommands) this.connection.get()).hset(name, key, value);
    }

    public String get(String key) {
        return (String) ((RedisCommands) this.connection.get()).get(key);
    }

    public boolean set(String key, String value) {
        return ((RedisCommands) this.connection.get()).set(key, value) != null;
    }

    public boolean del(String key) {
        return ((RedisCommands) this.connection.get()).del(new String[]{key}) != null;
    }

    public Map<String, String> hgetall(String name) {
        return ((RedisCommands) this.connection.get()).hgetall(name);
    }

    public void reset() {
        try {
            ((RedisCommands) this.connection.get()).reset();
        }
        catch (CancellationException var2) {
            ;
        }

    }

    public void register(RedisHandler handler) {
        this.handlers.add(handler);
        ((RedisPubSubCommands) this.pubSubCommands.get()).subscribe(handler.channels());
    }

    public void unRegister(RedisHandler handler) {
        this.handlers.remove(handler);
        ((RedisPubSubCommands) this.pubSubCommands.get()).unsubscribe(handler.channels());
    }

    public Collection<RedisHandler> handlers() {
        return this.handlers;
    }

    public void publish(RedisMessage message) {
        ((RedisCommands) this.connection.get()).publish(message.channel(), message.write().toString());
    }

    public void enable() {
        if (this.connection.isPresent()) {
            throw new IllegalStateException("Redis has already been enabled.");
        }
        else {
            StatefulRedisPubSubConnection<String, String> pubsub = this.client.connectPubSub();
            pubsub.addListener(new RedisListener(this));
            this.pubSubCommands = Optional.of(pubsub.sync());
            StatefulRedisConnection<String, String> connection = this.client.connect();
            this.connection = Optional.ofNullable(connection.sync());
        }
    }

    public void disable() {
        if (!this.connection.isPresent()) {
            throw new IllegalStateException("Redis hasn't been enabled.");
        }
        else {
            ((RedisCommands) this.connection.get()).getStatefulConnection().close();
            this.connection = Optional.empty();
        }
    }

    public static class Builder {

        private final String host;
        private final int port;
        private Optional<Integer> timeout = Optional.empty();
        private Optional<String> password = Optional.empty();
        private Optional<Integer> database = Optional.empty();
        private Optional<Boolean> reconnect = Optional.empty();

        public Builder(String host, int port) {
            this.host = host;
            this.port = port;
        }

        public Redis.Builder timeout(int timeout) {
            this.timeout = Optional.of(timeout);
            return this;
        }

        public Redis.Builder password(String password) {
            this.password = Optional.of(password);
            return this;
        }

        public Redis.Builder database(int database) {
            this.database = Optional.of(database);
            return this;
        }

        public Redis.Builder reconnect(boolean reconnect) {
            this.reconnect = Optional.of(reconnect);
            return this;
        }

        public Redis build() {
            io.lettuce.core.RedisURI.Builder uriBuilder = io.lettuce.core.RedisURI.Builder.redis(this.host, this.port);
            this.timeout.ifPresent((integer) -> {
                uriBuilder.withTimeout((long) integer, TimeUnit.MILLISECONDS);
            });
            this.database.ifPresent(uriBuilder::withDatabase);
            this.password.ifPresent(uriBuilder::withPassword);
            io.lettuce.core.ClientOptions.Builder options = ClientOptions.builder();
            this.reconnect.ifPresent(options::autoReconnect);
            return new Redis(uriBuilder.build(), options.build());
        }
    }
}
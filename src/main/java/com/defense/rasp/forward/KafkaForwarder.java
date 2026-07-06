package com.defense.rasp.forward;

@SuppressWarnings("unused")
public class KafkaForwarder implements Forwarder {

    private final Object producer;
    private final String topic;

    public KafkaForwarder() {
        throw new UnsupportedOperationException(
            "Kafka 客户端未集成。如需 Kafka 转发，请在 pom.xml 中添加 kafka-clients 依赖并重新编译。");
    }

    @Override
    public void send(String jsonMessage) {
    }

    @Override
    public void close() {
    }
}

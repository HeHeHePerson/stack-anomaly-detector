package com.defense.rasp.forward;

public interface Forwarder {
    void send(String jsonMessage);
    void close();
}

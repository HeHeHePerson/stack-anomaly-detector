package com.defense.rasp.forward;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class SyslogForwarder implements Forwarder {

    private static final int FACILITY_LOCAL0 = 16;
    private static final int SEVERITY_INFO = 6;
    private static final int PRI = (FACILITY_LOCAL0 * 8) + SEVERITY_INFO;

    private final InetAddress host;
    private final int port;
    private final DatagramSocket socket;
    private final String hostname;
    private final SimpleDateFormat dateFormat;

    SyslogForwarder(String hostAddr, int port) {
        try {
            this.host = InetAddress.getByName(hostAddr != null ? hostAddr : "localhost");
            this.port = (port > 0 && port <= 65535) ? port : 514;
            this.socket = new DatagramSocket();
            this.hostname = getLocalHostname();
            this.dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
            this.dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        } catch (Exception e) {
            throw new RuntimeException("SyslogForwarder初始化失败: " + e.getMessage(), e);
        }
    }

    @Override
    public void send(String jsonMessage) {
        try {
            String syslogMsg = buildSyslogMessage(jsonMessage);
            byte[] data = syslogMsg.getBytes("UTF-8");
            DatagramPacket packet = new DatagramPacket(data, data.length, host, port);
            socket.send(packet);
        } catch (Exception e) {
            System.err.println("[SyslogForwarder] 发送失败: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        try { socket.close(); } catch (Exception ignored) {}
    }

    private String buildSyslogMessage(String jsonMessage) {
        String timestamp = dateFormat.format(new Date());
        return "<" + PRI + ">1 " + timestamp + " " + hostname
                + " raspt-forwarder - - - " + jsonMessage;
    }

    private static String getLocalHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "localhost";
        }
    }
}

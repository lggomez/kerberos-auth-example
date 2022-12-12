package auth.kerberos.example.okhttp3.transport.ws;

import okhttp3.*;
import okio.ByteString;

import java.util.concurrent.CountDownLatch;

public final class ProxiedWebSocket extends WebSocketListener {
    private final OkHttpClient wsClient;
    private final CountDownLatch countDownLatch;

    public ProxiedWebSocket(OkHttpClient wsClient, CountDownLatch countDownLatch) {
        this.wsClient = wsClient;
        this.countDownLatch = countDownLatch;
    }

    public void close() {
        // Trigger shutdown of the dispatcher's executor so this process can exit cleanly.
        wsClient.dispatcher().executorService().shutdown();
    }

    public void run(String socketURL) throws InterruptedException {
        Request request = new Request.Builder()
                .url(socketURL)
                .build();
        WebSocket ws = wsClient.newWebSocket(request, this);

        for (int i = 0; i <= countDownLatch.getCount(); i++) {
            ws.send("Salute no." + i);
            Thread.sleep((long) (Math.random()*1000));
        }
    }

    @Override
    public void onOpen(WebSocket webSocket, Response response) {
        webSocket.send("Hello...");
        webSocket.send("...World!");
    }

    @Override
    public void onMessage(WebSocket webSocket, String text) {
        System.out.println("MESSAGE: " + text);
        countDownLatch.countDown();
    }

    @Override
    public void onMessage(WebSocket webSocket, ByteString bytes) {
        System.out.println("MESSAGE: " + bytes.hex());
        countDownLatch.countDown();
    }

    @Override
    public void onClosing(WebSocket webSocket, int code, String reason) {
        webSocket.close(1000, null);
        System.out.println("CLOSE: " + code + " " + reason);
    }

    @Override
    public void onFailure(WebSocket webSocket, Throwable t, Response response) {
        t.printStackTrace();
    }
}
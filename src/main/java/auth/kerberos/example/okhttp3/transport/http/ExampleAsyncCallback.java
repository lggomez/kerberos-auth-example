package auth.kerberos.example.okhttp3.transport.http;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;

public class ExampleAsyncCallback implements Callback {
    private final CountDownLatch countDownLatch;

    public ExampleAsyncCallback(CountDownLatch countDownLatch) {
        this.countDownLatch = countDownLatch;
    }

    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        e.printStackTrace();
        countDownLatch.countDown();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) {
        try (ResponseBody responseBody = response.body()) {
            if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);

            synchronized (this) {
                System.out.println("===================================================");
                System.out.printf("RESPONSE CODE (%s): %s%n",
                        call.request().url(),
                        responseBody.toString(),
                        response.code());

                System.out.println(responseBody.string());
                System.out.println("===================================================");
            }

            response.close();
            countDownLatch.countDown();
        } catch (Exception e) {
            System.out.printf("ERROR EXECUTING REQUEST: %s - %s", e.getMessage(), e.getCause());
        }
    }
}

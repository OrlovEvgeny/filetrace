import java.net.*;
import java.nio.file.*;

/** Posts a file with HttpURLConnection: java Up.java FILE URL */
public class Up {
    public static void main(String[] a) throws Exception {
        byte[] b = Files.readAllBytes(Paths.get(a[0]));
        HttpURLConnection c = (HttpURLConnection) URI.create(a[1]).toURL().openConnection();
        c.setDoOutput(true);
        c.setRequestMethod("POST");
        c.setFixedLengthStreamingMode(b.length);
        c.getOutputStream().write(b);
        c.getOutputStream().close();
        c.getResponseCode();
    }
}

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

public class JWKSServer {

    private static RsaJsonWebKey jwk = null;
    private static RsaJsonWebKey expiredJWK = null;

    public static void main(String[] args) throws Exception {
        // Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
        jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId("goodKey1");
        expiredJWK = RsaJwkGenerator.generateJwk(2048);
        expiredJWK.setKeyId("expiredKey");

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.well-known/jwks.json", new JWKSHandler());
        server.createContext("/auth", new AuthHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    static class JWKSHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            if (!"GET".equalsIgnoreCase(t.getRequestMethod())) {
                t.sendResponseHeaders(405, -1); // 405 Method Not Allowed
                return;
            }
            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwk);
            String jwks = jsonWebKeySet.toJson();
            t.getResponseHeaders().add("Content-Type", "application/json");
            t.sendResponseHeaders(200, jwks.length());
            OutputStream os = t.getResponseBody();
            os.write(jwks.getBytes());
            os.close();
        }
    }

    static class AuthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            if (!"POST".equalsIgnoreCase(t.getRequestMethod())) {
                t.sendResponseHeaders(405, -1); // 405 Method Not Allowed
                return;
            }
            JwtClaims claims = new JwtClaims();
            claims.setGeneratedJwtId();
            claims.setIssuedAtToNow();
            claims.setSubject("sampleUser");
            claims.setExpirationTimeMinutesInTheFuture(10);

            JsonWebSignature jws = new JsonWebSignature();
            jws.setKeyIdHeaderValue(jwk.getKeyId());
            jws.setKey(jwk.getPrivateKey());

            // Check for the "expired" query parameter
            if (t.getRequestURI().getQuery() != null && t.getRequestURI().getQuery().contains("expired=true")) {
                NumericDate expirationTime = NumericDate.now();
                expirationTime.addSeconds(-10 * 60); // Subtract 10 minutes
                claims.setExpirationTime(expirationTime);
                jws.setKeyIdHeaderValue(expiredJWK.getKeyId());
                jws.setKey(expiredJWK.getPrivateKey());
            }

            jws.setPayload(claims.toJson());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

            String jwt = "";
            try {
                jwt = jws.getCompactSerialization();
            } catch (JoseException e) {
                e.printStackTrace();
                t.sendResponseHeaders(500, -1); // 500 Internal Server Error
                return;
            }

            t.sendResponseHeaders(200, jwt.length());
            OutputStream os = t.getResponseBody();
            os.write(jwt.getBytes());
            os.close();
        }
    }
}

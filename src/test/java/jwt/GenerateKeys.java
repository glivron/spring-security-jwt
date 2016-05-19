package jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Test;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class GenerateKeys {

    @Test
    public void test() throws Exception {
        final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);

        final KeyPair keyPair = keyGenerator.genKeyPair();

        try (final FileOutputStream fos = new FileOutputStream("src/main/resources/public.key")) {
            fos.write(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()).getEncoded());
        }
        try (final FileOutputStream fos = new FileOutputStream("src/main/resources/private.key")) {
            fos.write(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()).getEncoded());
        }

        final String token = Jwts.builder()
                .setSubject("toto")
                .signWith(SignatureAlgorithm.RS384, keyPair.getPrivate())
                .compact();

        final Jws<Claims> jws = Jwts.parser()
                .setSigningKey(keyPair.getPublic())
                .parseClaimsJws(token);

        assertEquals("toto", jws.getBody().getSubject());
    }
}

package jwt.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Set;

import static java.lang.System.currentTimeMillis;
import static java.util.stream.Collectors.toSet;

public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    public static final String JWT_COOKIE = "JWT";

    public static final String AUTHORITIES_KEY = "AUTHORITIES";

    private final PrivateKey key;

    private final String successUrl;

    private final int expiry;

    public JwtAuthenticationSuccessHandler(final PrivateKey key, final String successUrl, final int expiry) {
        this.key = key;
        this.successUrl = successUrl;
        this.expiry = expiry;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        final Set<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toSet());

        final Date expiration = new Date(currentTimeMillis() + (expiry * 1000));

        final String token = Jwts.builder()
                .setExpiration(expiration)
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(SignatureAlgorithm.RS384, key)
                .compact();

        final Cookie cookie = new Cookie(JWT_COOKIE, token);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(expiry);
        response.addCookie(cookie);

        response.sendRedirect(successUrl);
    }
}

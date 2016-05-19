package jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static java.util.Collections.emptyList;
import static java.util.Optional.empty;
import static jwt.security.JwtAuthenticationSuccessHandler.AUTHORITIES_KEY;
import static jwt.security.JwtAuthenticationSuccessHandler.JWT_COOKIE;
import static org.slf4j.LoggerFactory.getLogger;

public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    private static final String EMPTY = "";

    private final Logger logger = getLogger(JwtAuthenticationProcessingFilter.class);

    private final PublicKey key;

    public JwtAuthenticationProcessingFilter(final PublicKey key) {
        this.key = key;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            extractJwtCookie(request)

                    .map(token -> Jwts.parser()
                            .setSigningKey(key)
                            .parseClaimsJws(token))

                    .map(jws -> {
                        final AbstractAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(jws.getBody().getSubject(), EMPTY, extractAuthorities(jws));
                        authentication.setDetails(jws);
                        return authentication;
                    })

                    .ifPresent(authentication -> SecurityContextHolder.getContext().setAuthentication(authentication));
        }
        catch (final Exception e) {
            logger.warn(e.getMessage(), e);
        }

        filterChain.doFilter(request, response);
    }

    private Optional<String> extractJwtCookie(final HttpServletRequest request) {
        final Cookie[] cookies = request.getCookies();

        if ((cookies == null) || (cookies.length == 0)) {
            return empty();
        }

        return stream(cookies)
                .filter(cookie -> JWT_COOKIE.equals(cookie.getName()))
                .map(Cookie::getValue)
                .map(String::trim)
                .findFirst();
    }

    @SuppressWarnings("unchecked")
    private Collection<? extends GrantedAuthority> extractAuthorities(final Jws<Claims> jws) {
        try {
            return ((Collection<String>) jws.getBody().get(AUTHORITIES_KEY))
                    .stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
        }
        catch (final Exception e) {
            logger.warn(e.getMessage(), e);
            return emptyList();
        }
    }
}

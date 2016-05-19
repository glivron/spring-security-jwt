package jwt.config;

import jwt.security.JwtAuthenticationProcessingFilter;
import jwt.security.JwtAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static jwt.security.JwtAuthenticationSuccessHandler.JWT_COOKIE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;
import static org.springframework.util.StreamUtils.copyToByteArray;

@Configuration
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PublicKey publicKey;

    private final PrivateKey privateKey;

    WebSecurityConfig() throws Exception {
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        final byte[] encodedPublicKey = copyToByteArray(new ClassPathResource("public.key").getInputStream());
        final byte[] encodedPrivateKey = copyToByteArray(new ClassPathResource("private.key").getInputStream());

        this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
        this.privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
    }

    @Override
    public void configure(final WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers(GET, "/favicon.ico");
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.csrf()
                .disable();

        http.sessionManagement()
                .sessionCreationPolicy(STATELESS);

        http.authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin()
                .successHandler(new JwtAuthenticationSuccessHandler(privateKey, "/", 60))
                .permitAll();

        http.logout()
                .deleteCookies(JWT_COOKIE)
                .permitAll();

        http.addFilterBefore(new JwtAuthenticationProcessingFilter(publicKey), UsernamePasswordAuthenticationFilter.class);
    }

    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("toto").password("toto").roles("USER");
    }
}

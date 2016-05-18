package jwt.config;

import jwt.security.JwtAuthenticationProcessingFilter;
import jwt.security.JwtAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static jwt.security.JwtAuthenticationSuccessHandler.JWT_COOKIE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("jwt.key")
    private String key;

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
                .successHandler(new JwtAuthenticationSuccessHandler(key, "/", 60))
                .permitAll();

        http.logout()
                .deleteCookies(JWT_COOKIE)
                .permitAll();

        http.addFilterBefore(new JwtAuthenticationProcessingFilter(key), UsernamePasswordAuthenticationFilter.class);
    }

    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("toto").password("toto").roles("USER");
    }
}

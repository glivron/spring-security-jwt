package jwt.web;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static java.util.Optional.ofNullable;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

@RestController
@RequestMapping("/whoami")
class WhoAmIController {

    final ResponseEntity UNAUTHORIZED = ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

    @RequestMapping(method = GET)
    ResponseEntity whoami(final Authentication authentication) {
        return ofNullable(authentication.getDetails())
                .map(details -> (Jws<Claims>) details)
                .map(Jwt::getBody)
                .map(ResponseEntity::ok)
                .orElse(UNAUTHORIZED);
    }
}

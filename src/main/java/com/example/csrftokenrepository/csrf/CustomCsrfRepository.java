package com.example.csrftokenrepository.csrf;

import com.example.csrftokenrepository.dao.TokenDao;
import com.example.csrftokenrepository.entity.Token;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class CustomCsrfRepository implements CsrfTokenRepository {
    private final TokenDao tokenDao;
    @Override
    public CsrfToken generateToken(HttpServletRequest request) {

        String uuid = UUID.randomUUID().toString();
        return new DefaultCsrfToken("X-CSRF-TOKEN","_csrf",uuid);
    }

    @Override
    public void saveToken(CsrfToken csrfToken, HttpServletRequest request, HttpServletResponse response) {

        String identifier = request.getHeader("X_IDENTIFIER");
        Optional<Token> existingToken = tokenDao
                .findTokenByIdentifier(identifier);
        if (existingToken.isPresent()){
            Token token = new Token();
            token.setToken(csrfToken.getToken());
        }
        else {
            Token token = new Token();
            token.setToken(csrfToken.getToken());
            token.setIdentifier(identifier);
            tokenDao.save(token);
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {

        String identifier = request.getHeader("X-IDENTIFIER");
        Optional<Token> existingToken = tokenDao
                .findTokenByIdentifier(identifier);
        if (existingToken.isPresent()){
            Token token = existingToken.get();
            return new DefaultCsrfToken("X-CSRF-TOKEN","_csrf", token.getToken());
        }
        return null;
    }
}

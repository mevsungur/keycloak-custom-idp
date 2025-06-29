package tr.gov.tkgm.keycloak.edevlet;

import jakarta.ws.rs.Path;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.jboss.logging.Logger;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.GET;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

public class EdevletIdentityProvider extends AbstractIdentityProvider<EdevletIdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(EdevletIdentityProvider.class);

    public EdevletIdentityProvider(KeycloakSession session, EdevletIdentityProviderConfig config) {
        super(session, config);
        logger.infof("EdevletIdentityProvider oluşturuldu. Config: %s", config.getConfigSummary());
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event, this);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            logger.info("E-devlet performLogin başlıyor");

            // Config geçerliliğini kontrol et
            if (!getConfig().isConfigValid()) {
                logger.error("E-devlet config geçersiz!");
                return ErrorPage.error(session, null, Response.Status.INTERNAL_SERVER_ERROR,
                        "E-devlet yapılandırması eksik veya hatalı");
            }

            String callbackUrl = session.getContext().getUri().getBaseUri() +
                    "realms/" + request.getRealm().getName() +
                    "/broker/" + getConfig().getAlias() + "/endpoint";

            logger.infof("Generated callback URL: %s", callbackUrl);

            String keycloakState = null;
            if (request.getAuthenticationSession() != null) {
                keycloakState = request.getAuthenticationSession().getClientNote("state");
            }
            logger.infof("PerformLogin'de Keycloak state: %s", keycloakState);

            String token = createJwtToken(keycloakState);
            logger.infof("JWT token oluşturuldu");

            // *** Config'den URL oluştur ***
            String edevletUrl = getConfig().buildEdevletUrl(token);
            logger.infof("E-devlet giriş için ara uygulamaya yönlendiriliyor: %s", edevletUrl);

            return Response.seeOther(URI.create(edevletUrl)).build();

        } catch (Exception e) {
            logger.error("E-devlet login hatası", e);
            return ErrorPage.error(session, null, Response.Status.INTERNAL_SERVER_ERROR,
                    "E-devlet giriş hatası: " + e.getMessage());
        }
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.ok(identity.getToken()).build();
    }

    private String createJwtToken(String keycloakState) {
        try {

            String jwtSecret = getConfig().getJwtSecret();

            if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
                throw new IdentityBrokerException("JWT secret yapılandırılmamış!");
            }

            long now = System.currentTimeMillis() / 1000;
            long exp = now + getConfig().getTokenExpirySeconds();

            String token = Jwts.builder()
                    .setHeaderParam("alg", "HS256")
                    .setHeaderParam("typ", "JWT")
                    .claim("TCNo", null)
                    .claim("ip", "127.0.0.1")
                    .claim("userrole", "kurum")
                    .claim("kc_state", keycloakState)
                    .claim("iat", now)
                    .claim("exp", exp)
                    .signWith(SignatureAlgorithm.HS256, jwtSecret.getBytes(StandardCharsets.UTF_8))
                    .compact();

            return token;

        } catch (Exception e) {
            logger.error("JWT token oluşturma hatası", e);
            throw new IdentityBrokerException("JWT token oluşturma hatası", e);
        }
    }

    protected static class Endpoint {
        protected AuthenticationCallback callback;
        protected RealmModel realm;
        protected EventBuilder event;
        protected KeycloakSession session;
        protected EdevletIdentityProvider provider;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, EdevletIdentityProvider provider) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
            this.session = provider.session;
            this.provider = provider;
        }

        @GET
        @Path("/")
        public Response get() {
            try {

                String sonuc = session.getContext().getUri().getQueryParameters().getFirst("sonuc");
                String error = session.getContext().getUri().getQueryParameters().getFirst("error");
                String errorDescription = session.getContext().getUri().getQueryParameters().getFirst("error_description");

                logger.infof("E-devlet callback - sonuc: %s, error: %s", (sonuc != null ? "var" : "yok"), error);

                if (error != null) {
                    logger.errorf("E-devlet authentication hatası: %s - %s", error, errorDescription);
                    return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "E-devlet authentication başarısız: " + error);
                }

                if (sonuc == null || sonuc.trim().isEmpty()) {
                    logger.error("E-devlet'ten sonuç parametresi alınamadı");
                    return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "E-devlet authentication başarısız: Sonuç parametresi eksik");
                }


                Claims claims = verifyJwtToken(sonuc);
                String tcNo = claims.get("TCNo", String.class);
                String state = claims.get("kc_state", String.class);

                if (state == null || state.trim().isEmpty()) {
                    logger.error("JWT'den kc_state alınamadı veya boş");
                    return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "Keycloak state eksik veya geçersiz");
                }


                AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
                RootAuthenticationSessionModel rootSession = asm.getCurrentRootAuthenticationSession(realm);
                if (rootSession == null) {
                    logger.errorf("Mevcut RootAuthenticationSession bulunamadı. State: %s", state);
                    return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "Keycloak root authentication session eksik");
                }


                AuthenticationSessionModel authSession = null;
                for (AuthenticationSessionModel asmItem : rootSession.getAuthenticationSessions().values()) {
                    String clientNoteState = asmItem.getClientNote("state");
                    logger.infof("AuthenticationSession clientNoteState: %s", clientNoteState);

                    if (state.equals(clientNoteState)) {
                        authSession = asmItem;
                        break;
                    }
                }

                if (authSession == null) {
                    logger.errorf("AuthenticationSession bulunamadı. Aranan state: %s", state);
                    return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "Keycloak authentication session eksik");
                }


                String ip = claims.get("ip", String.class);
                String userRole = claims.get("userrole", String.class);
                String nereden = claims.get("nereden", String.class);

                if (!nereden.equalsIgnoreCase("EDEVLETAUTH")) {
                    throw new IdentityBrokerException("Geri dönüşte e-devlet auth değeri yok");
                }


                Boolean isTwoFactor = claims.get("isTwoFactor", Boolean.class);
                String ad = null;
                String soyad = null;

                Object kullaniciBilgiObj = claims.get("KullaniciBilgi");
                if (kullaniciBilgiObj instanceof java.util.Map) {
                    java.util.Map<String, Object> kullaniciBilgi = (java.util.Map<String, Object>) kullaniciBilgiObj;
                    ad = (String) kullaniciBilgi.get("ad");
                    soyad = (String) kullaniciBilgi.get("soyad");
                }

                logger.infof("E-devlet'ten başarılı dönüş - TC: %s, Ad: %s, Soyad: %s, IP: %s, Role: %s, Nereden: %s",
                        tcNo, ad, soyad, ip, userRole, nereden);

                BrokeredIdentityContext identity = new BrokeredIdentityContext(tcNo);
                identity.setUsername(tcNo);
                identity.setEmail(null);
                identity.setFirstName(ad);
                identity.setLastName(soyad);
                identity.setIdpConfig(provider.getConfig());
                identity.setIdp(provider);
                identity.setAuthenticationSession(authSession);

                identity.getContextData().put("tcno", tcNo);
                identity.getContextData().put("ip", ip != null ? ip : "unknown");
                identity.getContextData().put("userrole", userRole != null ? userRole : "unknown");
                identity.getContextData().put("nereden", nereden != null ? nereden : "unknown");
                identity.getContextData().put("isTwoFactor", String.valueOf(isTwoFactor));
                if (ad != null) identity.getContextData().put("ad", ad);
                if (soyad != null) identity.getContextData().put("soyad", soyad);

                return callback.authenticated(identity);

            } catch (Exception e) {
                logger.error("E-devlet callback hatası", e);
                return ErrorPage.error(session, null, Response.Status.INTERNAL_SERVER_ERROR, "E-devlet authentication hatası: " + e.getMessage());
            }
        }

        private Claims verifyJwtToken(String token) {
            try {

                String jwtSecret = provider.getConfig().getJwtSecret();
                if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
                    throw new IdentityBrokerException("JWT secret yapılandırılmamış!");
                }

                return Jwts.parser()
                        .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
                        .parseClaimsJws(token)
                        .getBody();

            } catch (Exception e) {
                logger.error("JWT token doğrulama hatası", e);
                throw new IdentityBrokerException("JWT token doğrulama hatası: " + e.getMessage(), e);
            }
        }
    }
}

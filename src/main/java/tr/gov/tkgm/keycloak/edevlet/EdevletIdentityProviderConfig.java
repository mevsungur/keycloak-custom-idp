package tr.gov.tkgm.keycloak.edevlet;

import org.jboss.logging.Logger;
import org.keycloak.models.IdentityProviderModel;

public class EdevletIdentityProviderConfig extends IdentityProviderModel {

    private static final Logger logger = Logger.getLogger(EdevletIdentityProviderConfig.class);

    public static final String EDEVLET_URL = "edevletUrl";
    public static final String JWT_SECRET = "jwtSecret";
    public static final String FROM_PARAM = "fromParam";
    public static final String PORTAL_PARAM = "portalParam";
    public static final String TOKEN_EXPIRY_SECONDS = "tokenExpirySeconds";
    public static final String DISPLAY_NAME = "displayName";

    public EdevletIdentityProviderConfig() {
        super();
    }


    public EdevletIdentityProviderConfig(IdentityProviderModel model) {
        super();

        if (model != null) {
            setAlias(model.getAlias());
            setProviderId(model.getProviderId());
            setEnabled(model.isEnabled());
            setTrustEmail(model.isTrustEmail());
            setStoreToken(model.isStoreToken());
            setAddReadTokenRoleOnCreate(model.isAddReadTokenRoleOnCreate());
            setLinkOnly(model.isLinkOnly());
            setFirstBrokerLoginFlowId(model.getFirstBrokerLoginFlowId());
            setPostBrokerLoginFlowId(model.getPostBrokerLoginFlowId());

            if (model.getConfig() != null) {
                for (String key : model.getConfig().keySet()) {
                    String value = model.getConfig().get(key);
                    getConfig().put(key, value);
                    // logger.infof("Config kopyalandı: %s = %s", key, value);
                }
            }

        }
    }

    // ===========================================
    // E-DEVLET KONFİGÜRASYON METODLARI
    // ===========================================

    public String getEdevletUrl() {
        String value = getConfig().get(EDEVLET_URL);
        logger.infof("getEdevletUrl() = %s", value);
        return value;
    }

    public void setEdevletUrl(String edevletUrl) {
        getConfig().put(EDEVLET_URL, edevletUrl);
        logger.infof("setEdevletUrl(%s)", edevletUrl);
    }

    public String getJwtSecret() {
        String value = getConfig().get(JWT_SECRET);
        logger.infof("getJwtSecret() = %s", value != null ? "[SET]" : "null");
        return value;
    }

    public void setJwtSecret(String jwtSecret) {
        getConfig().put(JWT_SECRET, jwtSecret);
        logger.infof("setJwtSecret([HIDDEN])");
    }

    public String getFromParam() {
        String value = getConfig().getOrDefault(FROM_PARAM, "TAKBIS2");
        logger.infof("getFromParam() = %s", value);
        return value;
    }

    public void setFromParam(String fromParam) {
        getConfig().put(FROM_PARAM, fromParam);
    }

    public String getPortalParam() {
        String value = getConfig().getOrDefault(PORTAL_PARAM, "Kurum");
        logger.infof("getPortalParam() = %s", value);
        return value;
    }

    public void setPortalParam(String portalParam) {
        getConfig().put(PORTAL_PARAM, portalParam);
    }

    public int getTokenExpirySeconds() {
        String expiry = getConfig().getOrDefault(TOKEN_EXPIRY_SECONDS, "300");
        try {
            int value = Integer.parseInt(expiry);
            logger.infof("getTokenExpirySeconds() = %d", value);
            return value;
        } catch (NumberFormatException e) {
            logger.warn("Token expiry parse hatası, varsayılan değer kullanılıyor: 300");
            return 300;
        }
    }

    public void setTokenExpirySeconds(int expirySeconds) {
        getConfig().put(TOKEN_EXPIRY_SECONDS, String.valueOf(expirySeconds));
    }


    public String getDisplayName() {
        return getConfig().getOrDefault(DISPLAY_NAME, "E-Devlet");
    }

    public void setDisplayName(String displayName) {
        getConfig().put(DISPLAY_NAME, displayName);
    }

    // ===========================================
    // KEYCLOAK STANDART KONFİGÜRASYON OVERRIDE'LAR
    // ===========================================

    @Override
    public boolean isStoreToken() {
        return Boolean.parseBoolean(getConfig().getOrDefault("storeToken", "false"));
    }

    @Override
    public void setStoreToken(boolean storeToken) {
        getConfig().put("storeToken", String.valueOf(storeToken));
    }

    @Override
    public boolean isTrustEmail() {
        return Boolean.parseBoolean(getConfig().getOrDefault("trustEmail", "false"));
    }

    @Override
    public void setTrustEmail(boolean trustEmail) {
        getConfig().put("trustEmail", String.valueOf(trustEmail));
    }

    @Override
    public boolean isLinkOnly() {
        return Boolean.parseBoolean(getConfig().getOrDefault("accountLinkingOnly", "false"));
    }

    @Override
    public void setLinkOnly(boolean linkOnly) {
        getConfig().put("accountLinkingOnly", String.valueOf(linkOnly));
    }

    // ===========================================
    // YARDIMCI METODLAR
    // ===========================================

    public boolean isConfigValid() {
        boolean valid = getEdevletUrl() != null && !getEdevletUrl().trim().isEmpty() &&
                getJwtSecret() != null && !getJwtSecret().trim().isEmpty();
        logger.infof("isConfigValid() = %b", valid);
        return valid;
    }

    public String buildEdevletUrl(String token) {
        String result = getEdevletUrl() + "?from=" + getFromParam() +
                "&state=" + token +
                "&portal=" + getPortalParam();
        logger.infof("buildEdevletUrl() = %s", result);
        return result;
    }

    public String getConfigSummary() {
        return String.format(
                "EdevletConfig{url='%s', from='%s', portal='%s', tokenExpiry=%d, trustEmail=%b, storeToken=%b}",
                getEdevletUrl(),
                getFromParam(),
                getPortalParam(),
                getTokenExpirySeconds(),
                isTrustEmail(),
                isStoreToken()
        );
    }
}

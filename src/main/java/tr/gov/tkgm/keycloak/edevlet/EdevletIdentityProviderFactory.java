package tr.gov.tkgm.keycloak.edevlet;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class EdevletIdentityProviderFactory extends AbstractIdentityProviderFactory<EdevletIdentityProvider> {

    public static final String PROVIDER_ID = "edevlet";

    @Override
    public String getName() {
        return "E-Devlet";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    @Override
    public EdevletIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new EdevletIdentityProvider(session, new EdevletIdentityProviderConfig(model));
    }

    @Override
    public EdevletIdentityProviderConfig createConfig() {
        return new EdevletIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()

                .property()
                .name(EdevletIdentityProviderConfig.EDEVLET_URL)  // "edevletUrl"
                .label("E-Devlet Giriş URL")
                .helpText("E-Devlet portal giriş URL'si")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("https://online.tkgm.gov.tr/giris")
                .add()

                .property()
                .name(EdevletIdentityProviderConfig.JWT_SECRET)
                .label("JWT Secret Key")
                .helpText("E-Devlet JWT token imzalama için gizli anahtar")
                .type(ProviderConfigProperty.PASSWORD)
                .defaultValue("")
                .add()

                .property()
                .name(EdevletIdentityProviderConfig.FROM_PARAM)
                .label("From Parametresi")
                .helpText("E-Devlet'e gönderilen 'from' parametresi")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("TAKBIS2")
                .add()

                .property()
                .name(EdevletIdentityProviderConfig.PORTAL_PARAM)
                .label("Portal Parametresi")
                .helpText("E-Devlet'e gönderilen 'portal' parametresi")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("Kurum")
                .add()

                .property()
                .name(EdevletIdentityProviderConfig.TOKEN_EXPIRY_SECONDS)
                .label("Token Geçerlilik Süresi (Saniye)")
                .helpText("JWT token'ın geçerlilik süresi")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("300")
                .add()


                .property()
                .name(EdevletIdentityProviderConfig.DISPLAY_NAME)
                .label("Görünen Ad")
                .helpText("Login sayfasında görünecek buton adı")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("E-Devlet ile Giriş")
                .add()

                // Keycloak standart ayarları
                .property()
                .name("storeToken")
                .label("Token Sakla")
                .helpText("E-Devlet token'ını veritabanında sakla")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()

                .property()
                .name("trustEmail")
                .label("Email Güven")
                .helpText("E-devlet'ten gelen email adresine güven")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()

                .property()
                .name("accountLinkingOnly")
                .label("Sadece Hesap Bağlama")
                .helpText("Sadece mevcut hesapları bağlamak için kullan")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()

                .build();
    }


}

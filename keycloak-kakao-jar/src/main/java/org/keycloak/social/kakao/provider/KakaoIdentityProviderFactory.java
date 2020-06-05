package org.keycloak.social.kakao.provider;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class KakaoIdentityProviderFactory extends AbstractIdentityProviderFactory<KakaoIdentityProvider> implements SocialIdentityProviderFactory<KakaoIdentityProvider> {

    public static final String PROVIDER_ID = "kakao";

    @Override
    public String getName() {
        return "Kakao";
    }

    @Override
    public KakaoIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new KakaoIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}

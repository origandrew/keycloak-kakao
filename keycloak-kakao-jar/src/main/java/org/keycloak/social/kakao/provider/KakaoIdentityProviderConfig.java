package org.keycloak.social.kakao.provider;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class KakaoIdentityProviderConfig extends OAuth2IdentityProviderConfig{

	public KakaoIdentityProviderConfig(IdentityProviderModel model) {
		super(model);
	}
}

package org.keycloak.social.kakao.provider;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

public class KakaoIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
	implements SocialIdentityProvider<OAuth2IdentityProviderConfig>{
	
	public static final String AUTH_URL = "https://kauth.kakao.com/oauth/authorize";
	public static final String TOKEN_URL = "https://kauth.kakao.com/oauth/token";
	public static final String PROFILE_URL = "https://kapi.kakao.com/v2/user/me";
	public static final String EMAIL_SCOPE = "account_email";
	public static final String DEFAULT_SCOPE = "profile " + EMAIL_SCOPE;


	public KakaoIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
		super(session, config);
		config.setAuthorizationUrl(AUTH_URL);
		config.setTokenUrl(TOKEN_URL);
		config.setUserInfoUrl(PROFILE_URL);
		
		// email scope is mandatory in order to resolve the username using the email address
		if (!config.getDefaultScope().contains(EMAIL_SCOPE)) {
			config.setDefaultScope(config.getDefaultScope() + " " + EMAIL_SCOPE);
		}
	}

	@Override
	protected boolean supportsExternalExchange() {
		return true;
	}

	@Override
	protected String getProfileEndpointForValidation(EventBuilder event) {
		return PROFILE_URL;
	}

	@Override
	protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
	    JsonNode properties = profile.get("properties");
	    JsonNode account = profile.get("kakao_account");

		final BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "id"));

		user.setUsername(getJsonProperty(account, "email"));
		user.setName(getJsonProperty(properties, "nickname"));
		user.setEmail(getJsonProperty(account, "email"));
		user.setIdpConfig(getConfig());
		user.setIdp(this);

		AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

		return user;
	}

	@Override
	protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
		try {
			BrokeredIdentityContext identity = extractIdentityFromProfile(null, doHttpGet(PROFILE_URL, accessToken));
			
			if (identity.getUsername() == null) {
				identity.setUsername(identity.getEmail());
			}
			
			return identity;
		} catch (Exception e) {
			throw new IdentityBrokerException("Could not obtain user profile from kakao.", e);
		}
	}

	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}

	private JsonNode doHttpGet(String url, String accessToken) throws IOException {
		JsonNode response = SimpleHttp.doGet(PROFILE_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
		
		if (response.hasNonNull("serviceErrorCode")) {
			throw new IdentityBrokerException("Could not obtain response from [" + url + "]. Reponse from server: " + response);
		}
		
		return response;
	}
}

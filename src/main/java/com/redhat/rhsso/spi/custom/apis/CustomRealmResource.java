package com.redhat.rhsso.spi.custom.apis;

import java.util.Collections;

import javax.ws.rs.FormParam;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuthErrorException;
import org.keycloak.authorization.util.Tokens;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.admin.OperationType;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.account.UserRepresentation;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.UserInfoRequestContext;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.utils.StringUtil;


public class CustomRealmResource extends AdminRoot implements RealmResourceProvider {

    protected static final Logger logger = Logger.getLogger(CustomRealmResource.class);

    @Context
    private HttpRequest request;

    @Context 
    private HttpHeaders headers;

    @Context
    protected ClientConnection clientConnection;

    private KeycloakSession session;

    protected TokenManager tokenManager;

    private AdminPermissionEvaluator auth;

    private AdminEventBuilder adminEvent; // admin events

    private EventBuilder event; // logins event

    private RealmModel realm;

    private Cors cors;

    public CustomRealmResource(KeycloakSession session, RealmModel realm, EventBuilder event) {
        this.session = session;
        this.tokenManager = new TokenManager();
        this.event = event;
        this.realm = realm;
    }

    private void configureAdminAuth() {
        AdminAuth auth = authenticateRealmAdminRequest(this.headers);
        this.auth = AdminPermissions.evaluator(session, realm, auth);
        this.adminEvent = new AdminEventBuilder(realm, auth, session, clientConnection);
    }

    @Override
    public Object getResource() {
        return this;
    }

    protected AdminAuth authenticateRealmAdminRequest(HttpHeaders headers) {
        String tokenString = AppAuthManager.extractAuthorizationHeaderToken(headers);
        if (tokenString == null) throw new NotAuthorizedException("Bearer");
        AccessToken token;
        try {
            JWSInput input = new JWSInput(tokenString);
            token = input.readJsonContent(AccessToken.class);
        } catch (JWSInputException e) {
            throw new NotAuthorizedException("Bearer token format error");
        }
        String realmName = token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        if (realm == null) {
            throw new NotAuthorizedException("Unknown realm in token");
        }
        session.getContext().setRealm(realm);

        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session)
                .setRealm(realm)
                .setConnection(clientConnection)
                .setHeaders(headers)
                .authenticate();

        if (authResult == null) {
            logger.debug("Token not valid");
            throw new NotAuthorizedException("Bearer");
        }

        return new AdminAuth(realm, authResult.getToken(), authResult.getUser(), authResult.getClient());
    }

    private CorsErrorResponseException newUnauthorizedErrorResponseException(String oauthError, String errorMessage) {
        // See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
        response.getOutputHeaders().put(HttpHeaders.WWW_AUTHENTICATE, Collections.singletonList(String.format("Bearer realm=\"%s\", error=\"%s\", error_description=\"%s\"", realm.getName(), oauthError, errorMessage)));
        return new CorsErrorResponseException(cors, oauthError, errorMessage, Response.Status.UNAUTHORIZED);
    }

    @POST
    @Path("/any-user/username-exists")
    @Produces(MediaType.TEXT_PLAIN + "; charset=utf-8")
    public Response authenticatedApi(@FormParam("username") String username) {

        String accessToken = getBearerToken();

        cors = Cors.add(request).auth().allowedMethods(request.getHttpMethod()).auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        //Example of client policy usage, using the same as calling a user info endpoint
        try {
            session.clientPolicy().triggerOnEvent(new UserInfoRequestContext(accessToken));
        } catch (ClientPolicyException cpe) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), cpe.getError(), cpe.getErrorDetail(), cpe.getErrorStatus());
        }

        if (accessToken == null) {
            event.error(Errors.INVALID_TOKEN);
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "Token not provided", Response.Status.BAD_REQUEST);
        }

        AccessToken accessTokenVerified = Tokens.getAccessToken(accessToken, session);

        if (accessTokenVerified == null) {
            event.error(Errors.INVALID_TOKEN);
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Token verification failed");
        } else if (!accessTokenVerified.getRealmAccess().isUserInRole("custom-api")) { 
            throw new ErrorResponseException("User or Service Account not authorized to execute that api","", Response.Status.FORBIDDEN);
        }

        ClientModel clientModel = null;
        clientModel = realm.getClientByClientId(accessTokenVerified.getIssuedFor());
        if (clientModel == null) {
            event.error(Errors.CLIENT_NOT_FOUND);
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "Client not found", Response.Status.BAD_REQUEST);
        }
        cors.allowedOrigins(session, clientModel);

        if (!clientModel.getProtocol().equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            event.error(Errors.INVALID_CLIENT);
            throw new CorsErrorResponseException(cors, Errors.INVALID_CLIENT, "Wrong client protocol.", Response.Status.BAD_REQUEST);
        }

        if (!clientModel.isEnabled()) {
            event.error(Errors.CLIENT_DISABLED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "Client disabled", Response.Status.BAD_REQUEST);
        }
        
        //verify username after token and client validation
        String responseMessage = checkUsername(username);
        return cors.builder(Response.ok(responseMessage)).build();
    }

    private String getBearerToken() {
        // Try header first
        HttpHeaders headers = request.getHttpHeaders();
        String accessToken = AppAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);

        // Fallback to form parameter
        if (accessToken == null) {
            accessToken = request.getDecodedFormParameters().getFirst("access_token");
        }
        return accessToken;
    }

    @POST
    @Path("/only-realm-admin/username-exists")
    @Produces(MediaType.TEXT_PLAIN + "; charset=utf-8")
    public Response onlyRealmAdmin(@FormParam("username") String username) {

        this.configureAdminAuth();
        // check if user has manage rights
        try {
            //require realm-role manage-users
            auth.users().requireManage();
        } catch (ForbiddenException exception) {
            throw exception;
        }

        Cors.add(request).allowedOrigins(auth.adminAuth().getToken()).allowedMethods("GET", "PUT", "POST", "DELETE").exposedHeaders("Location").auth().build(response);

        String responseMessage = checkUsername(username);
      
        UserRepresentation user =  new UserRepresentation();
        user.setUsername(username);

        adminEvent.operation(OperationType.ACTION).resourcePath(session.getContext().getUri(), username).representation(user).success();

        return Response.ok(responseMessage).build();
    }

    private String checkUsername(String username) {
        String responseMessage = null;
        if(StringUtil.isNotBlank(username)) {
            RealmModel realm = session.getContext().getRealm();
            UserModel user = KeycloakModelUtils.findUserByNameOrEmail(session, realm, username);
            responseMessage = user != null ? "Username: ".concat(username).concat(", already exist!") : "Username: ".concat(username).concat(", does not exist in the realm yet");
        
        } else {
            throw new ErrorResponseException("username not informed","", Response.Status.BAD_REQUEST);
        }
        return responseMessage;
    }

    @Override
    public void close() {
        logger.info("closing custom-api resources ...");
    }
}

package com.redhat.rhsso.spi.custom.apis;

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
import org.keycloak.authorization.util.Tokens;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.account.UserRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;


public class CustomRealmResource extends AdminRoot implements RealmResourceProvider {

    protected static final Logger logger = Logger.getLogger(CustomRealmResource.class);

    @Context
    private HttpRequest request;

    @Context 
    private HttpHeaders headers;

    private KeycloakSession session;

    protected TokenManager tokenManager;

    private AdminPermissionEvaluator auth;

    private AdminEventBuilder adminEvent;

    public CustomRealmResource(KeycloakSession session) {
        this.session = session;
        this.tokenManager = new TokenManager();
        AdminAuth auth = authenticateRealmAdminRequest(this.headers);
        RealmModel realm =  session.getContext().getRealm();
        this.auth = AdminPermissions.evaluator(session, realm, auth);
        this.adminEvent = adminEvent.resource(ResourceType.USER);
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

    @POST
    @Path("any-user/username-exists")
    @Produces(MediaType.TEXT_PLAIN + "; charset=utf-8")
    public Response authenticatedApi(@FormParam("username") String username) {

        // Try header first
        HttpHeaders headers = request.getHttpHeaders();
        String accessToken = AppAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);

        // Fallback to form parameter
        if (accessToken == null) {
            accessToken = request.getDecodedFormParameters().getFirst("access_token");
        }

        AccessToken accessTokenVerified = Tokens.getAccessToken(accessToken, session);

        if (accessTokenVerified == null) {
            throw new ErrorResponseException("Thes access_token provided is invalid","", Response.Status.UNAUTHORIZED);
        } else if (!accessTokenVerified.getRealmAccess().isUserInRole("custom-api")) { 
            throw new ErrorResponseException("User or Service Account not authorized to execute that api","", Response.Status.FORBIDDEN);
        }

        //verify username after token validation
        String responseMessage = checkUsername(username);
        return Response.ok(responseMessage).build();
    }

    @POST
    @Path("only-realm-admin/username-exists")
    @Produces(MediaType.TEXT_PLAIN + "; charset=utf-8")
    public Response onlyRealmAdmin(@FormParam("username") String username) {

        // check if user has manage rights
        try {
            auth.users().requireManage();
        } catch (ForbiddenException exception) {
            throw exception;
        }
       
        UserRepresentation user =  new UserRepresentation();
        user.setUsername(username);

        adminEvent.operation(OperationType.ACTION).resourcePath(session.getContext().getUri(), username).representation(user).success();
        String responseMessage = checkUsername(username);
        return Response.ok(responseMessage).build();
    }

    private String checkUsername(String username) {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = KeycloakModelUtils.findUserByNameOrEmail(session, realm, username);
        String responseMessage = user != null ? "Username: ".concat(username).concat(", already exist!") : "Username: ".concat(username).concat(", does not exist in the realm yet");
        return responseMessage;
    }

    @Override
    public void close() {
        logger.info("closing custom-api resources ...");
    }
}

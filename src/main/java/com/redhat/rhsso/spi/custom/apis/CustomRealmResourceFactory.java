package com.redhat.rhsso.spi.custom.apis;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class CustomRealmResourceFactory implements RealmResourceProviderFactory {

    protected static final Logger logger = Logger.getLogger(CustomRealmResourceFactory.class);
    
    private static final String PROVIDER_ID = "custom-api";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new CustomRealmResource(session);
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
        logger.debug("closing: custom realm resource provider factory");
    }
}

package org.keycloak.example.authcode;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.Response;

public class SecretCodeAuth implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UsernamePasswordForm usernamePasswordForm = new UsernamePasswordForm();
        usernamePasswordForm.authenticate(context);


        Response challenge = context.form().createForm("seccode.ftl");
        context.challenge(challenge);

    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String secretCode = context.getHttpRequest().getDecodedFormParameters().getFirst("seccode");
        String expectedCode = "555";

        if(secretCode==null||!secretCode.equals(expectedCode)){
            Response response = context.form()
                            .setError("badCode")
                                    .createForm("seccode.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            return;
        }
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }
}

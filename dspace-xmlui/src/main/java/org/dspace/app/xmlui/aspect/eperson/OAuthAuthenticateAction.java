/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.app.xmlui.aspect.eperson;

import java.io.IOException;

import java.util.Map;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.api.client.http.*;
import com.google.api.client.json.JsonObjectParser;
import org.apache.avalon.framework.parameters.Parameters;
import org.apache.cocoon.acting.AbstractAction;
import org.apache.cocoon.environment.ObjectModelHelper;
import org.apache.cocoon.environment.Redirector;
import org.apache.cocoon.environment.Request;
import org.apache.cocoon.environment.SourceResolver;
import org.apache.cocoon.environment.http.HttpEnvironment;
import org.dspace.app.xmlui.utils.AuthenticationUtil;
import org.dspace.app.xmlui.utils.ContextUtil;
import org.dspace.core.ConfigurationManager;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;
import com.google.api.client.auth.oauth2.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;

/**
 * Attempt to authenticate through OAuth2 mechanism
 *
 * @author Artur Komarov
 */

public class OAuthAuthenticateAction extends AbstractAction {

    /**
     * Directory to store user credentials.
     */
    private static final java.io.File DATA_STORE_DIR =
            new java.io.File(System.getProperty("user.home"), ".store/liot_sample");

    /**
     * Global instance of the HTTP transport.
     */
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

    /**
     * Global instance of the JSON factory.
     */
    static final JsonFactory JSON_FACTORY = new JacksonFactory();

    private static AuthorizationCodeFlow flow;

    private EPerson createUser(Context context, OAuthProfile oAuthProfile) throws Exception {
        System.out.println("trying to find user by email: " + oAuthProfile.email);
        EPerson eperson = EPerson.findByEmail(context, oAuthProfile.email);

        // check if the email belongs to a registered user,
        // if not create a new user with this email
        if (eperson == null) {
            context.turnOffAuthorisationSystem();
            System.out.println("account doesn't exists, creation...");
            eperson = EPerson.create(context);
            eperson.setEmail(oAuthProfile.email);
            eperson.setCanLogIn(true);
            eperson.setRequireCertificate(false);
            eperson.setSelfRegistered(false);
            eperson.setLastName(oAuthProfile.surname);
            eperson.setFirstName(oAuthProfile.name);
            eperson.update();
            context.restoreAuthSystemState();
        } else {
            System.out.println("account already exists");
        }

        // authorize
        return eperson;
    }

    /**
     * Attempt to authenticate the user.
     */
    public Map act(Redirector redirector, SourceResolver resolver, Map objectModel,
                   String source, Parameters parameters) throws Exception {
        Request request = ObjectModelHelper.getRequest(objectModel);
        Context context = ContextUtil.obtainContext(objectModel);
        HttpSession session = request.getSession();

        if (session.getAttribute("flow") != null) {
            flow = (AuthorizationCodeFlow) session.getAttribute("flow");
        } else {
            flow = new AuthorizationCodeFlow.Builder(BearerToken
                    .authorizationHeaderAccessMethod(),
                    HTTP_TRANSPORT,
                    JSON_FACTORY,
                    new GenericUrl(ConfigurationManager.getProperty("xmlui.user.oauth.token_url")),
                    new ClientParametersAuthentication(
                            ConfigurationManager.getProperty("xmlui.user.oauth.key"),
                            ConfigurationManager.getProperty("xmlui.user.oauth.secret")),
                    ConfigurationManager.getProperty("xmlui.user.oauth.key"),
                    ConfigurationManager.getProperty("xmlui.user.oauth.authorization_url"))
                    .setDataStoreFactory(new FileDataStoreFactory(DATA_STORE_DIR))
                    .build();
        }

        // Check if user already authorized
        // XXX: id "user" - can not WORK!!!!
        final Credential credential = flow.loadCredential("user");
        if (credential != null
                && (credential.getRefreshToken() != null
                || credential.getExpiresInSeconds() != null && credential.getExpiresInSeconds() > 60)) {
            System.out.println("already authorized");

            // test request
            HttpRequestFactory requestFactory =
                    HTTP_TRANSPORT.createRequestFactory(new HttpRequestInitializer() {
                        @Override
                        public void initialize(HttpRequest request) throws IOException {
                            credential.initialize(request);
                        }
                    });
            GenericUrl url = new GenericUrl("http://liot.mipt.ru/api/me");
            url.set("access_token", credential.getAccessToken());
            System.out.println("request result: " + requestFactory.buildGetRequest(url).execute().parseAsString());

            // request for already stored credential

            return null;
        }

        // send token request if code received
        String code = request.getParameter("code");
        if (code != null) {
            TokenResponse response = flow.newTokenRequest(code).setRedirectUri("http://localhost:8080" + request.getContextPath() + "/oauth-login").execute();
            System.out.println("response token 2: " + response.getAccessToken());
            flow.createAndStoreCredential(response, "user").setExpirationTimeMilliseconds(3600L);

            HttpRequestFactory requestFactory =
                    HTTP_TRANSPORT.createRequestFactory(new HttpRequestInitializer() {
                        @Override
                        public void initialize(HttpRequest request) throws IOException {
                            credential.initialize(request);
                            request.setParser(new JsonObjectParser(JSON_FACTORY));
                        }
                    });
            GenericUrl url = new GenericUrl("http://liot.mipt.ru/api/me");
            url.set("access_token", credential.getAccessToken());

            HttpResponse httpResponse = requestFactory.buildGetRequest(url).execute();
            OAuthProfile oauthProfile = httpResponse.parseAs(OAuthProfile.class);
            AuthenticationUtil.logIn(objectModel, createUser(context, oauthProfile));
            ((HttpServletResponse) objectModel.get(HttpEnvironment.HTTP_RESPONSE_OBJECT))
                    .sendRedirect(new GenericUrl("http://localhost:8080" + request.getContextPath() + "/").toString());

            return null;
        }

        // save flow to continue oauth process
        session.setAttribute("flow", flow);

        // redirect to oauth authorization process
        AuthorizationCodeRequestUrl authorizationUrl = flow.newAuthorizationUrl().setRedirectUri("http://localhost:8080" + request.getContextPath() + "/oauth-login");
        final HttpServletResponse httpResponse = (HttpServletResponse) objectModel.get(HttpEnvironment.HTTP_RESPONSE_OBJECT);
        httpResponse.sendRedirect(authorizationUrl.toString());

        return null;
    }
}


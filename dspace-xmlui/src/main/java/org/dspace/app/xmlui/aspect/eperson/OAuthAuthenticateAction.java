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
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

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
import org.dspace.eperson.Group;
import com.google.api.client.auth.oauth2.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;

/**
 * Attempt to authenticate through OAuth2 mechanism
 *
 * @author Artur Komarov
 */

public class OAuthAuthenticateAction extends AbstractAction {

    /**
     * Global instance of the HTTP transport.
     */
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

    /**
     * Global instance of the JSON factory.
     */
    static final JsonFactory JSON_FACTORY = new JacksonFactory();

    private static AuthorizationCodeFlow flow;

    private EPerson createUser(Context context, OAuthProfile oAuthEmail, OAuthProfile oAuthUserinfo) throws Exception {
        String netId = oAuthUserinfo.id.toString() + '@' + ConfigurationManager.getProperty("xmlui.user.oauth.domain");

        System.out.println("trying to find user by netid: " + netId);

        EPerson eperson = EPerson.findByNetid(context, netId);

        // authorize by email if exists
        if (eperson == null && !oAuthEmail.email.isEmpty()) {
            eperson = EPerson.findByEmail(context, oAuthEmail.email);
        }

        // check if the email belongs to a registered user,
        // if not create a new user with this email

        String defaultGroup = ConfigurationManager.getProperty("xmlui.user.oauth.default_group");

        if (eperson == null) {
            context.turnOffAuthorisationSystem();
            System.out.println("account doesn't exists, creation...");
            eperson = EPerson.create(context);
            eperson.setNetid(netId);
            eperson.setEmail(oAuthEmail.email);
            eperson.setCanLogIn(true);
            eperson.setRequireCertificate(false);
            eperson.setSelfRegistered(false);
            eperson.setLastName(oAuthUserinfo.lastname);
            eperson.setFirstName(oAuthUserinfo.firstname);
            eperson.update();
            if (defaultGroup != null) {
              Group miptusers = Group.find(context, Integer.parseInt(defaultGroup));
              if (miptusers == null)
              {
                throw new IllegalStateException("Error, no mipt users group (group 11) found");
              }
              miptusers.addMember(eperson);
              miptusers.update();
            }

            context.restoreAuthSystemState();
        } else {
            System.out.println("account already exists");
        }

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
            AuthorizationCodeFlow.Builder builder = new AuthorizationCodeFlow.Builder(BearerToken
                    .authorizationHeaderAccessMethod(),
                    HTTP_TRANSPORT,
                    JSON_FACTORY,
                    new GenericUrl(ConfigurationManager.getProperty("xmlui.user.oauth.token_url")),
                    new ClientParametersAuthentication(
                            ConfigurationManager.getProperty("xmlui.user.oauth.key"),
                            ConfigurationManager.getProperty("xmlui.user.oauth.secret")),
                    ConfigurationManager.getProperty("xmlui.user.oauth.key"),
                    ConfigurationManager.getProperty("xmlui.user.oauth.authorization_url"));
            // save flow to continue oauth process
            List<String> scopes = Arrays.asList(
              "email",
              "userinfo",
              "student",
              "diploma"
            );
            builder.setScopes(scopes);
            flow = builder.build();
            session.setAttribute("flow", flow);
        }

        // send token request if code received
        String code = request.getParameter("code");
        if (code != null) {
            System.out.println("got code");
            TokenResponse response = flow.newTokenRequest(code).setRedirectUri(
                    ConfigurationManager.getProperty("dspace.baseUrl") + request.getContextPath() + "/oauth-login").execute();

            HttpRequestFactory requestFactory =
                    HTTP_TRANSPORT.createRequestFactory(new HttpRequestInitializer() {
                        @Override
                        public void initialize(HttpRequest request) throws IOException {
                            //credential.initialize(request);
                            request.setParser(new JsonObjectParser(JSON_FACTORY));
                        }
                    });

            // save access_token next usage
            session.setAttribute("access_token", response.getAccessToken());

            GenericUrl url = new GenericUrl(ConfigurationManager.getProperty("xmlui.user.oauth.profile_url"));
            url.set("access_token", response.getAccessToken());
            url.set("get", "email");

            HttpResponse httpResponse = requestFactory.buildGetRequest(url).execute();
            OAuthProfile oAuthEmail = httpResponse.parseAs(OAuthProfile.class);

            url.set("get", "userinfo");
            httpResponse = requestFactory.buildGetRequest(url).execute();
            OAuthProfile oAuthUserinfo = httpResponse.parseAs(OAuthProfile.class);

            // url.set("get", "student");
            // httpResponse = requestFactory.buildGetRequest(url).execute();
            // OAuthProfile oAuthStudent = httpResponse.parseAs(OAuthProfile.class);

            HttpServletResponse redirectResponse = ((HttpServletResponse) objectModel.get(HttpEnvironment.HTTP_RESPONSE_OBJECT));
            if (!oAuthEmail.email.split("@")[1].equals("phystech.edu") && !oAuthEmail.email.split("@")[1].equals("mipt.ru")) {
              // redirect to main page if not student
              redirectResponse.sendRedirect("http://mipt.ru");
              return null;
            }

            EPerson ePerson = createUser(context, oAuthEmail, oAuthUserinfo);
            AuthenticationUtil.logIn(objectModel, ePerson);

            // GenericUrl redirectUrl = new GenericUrl("http://localhost:8080" + request.getContextPath() + "/");
            // HttpServletResponse redirectResponse = ((HttpServletResponse) objectModel.get(HttpEnvironment.HTTP_RESPONSE_OBJECT));

            //String redirectURL = session.getAttribute("resumeURL").toString();
            //session.removeAttribute("resumeURL");

            //System.out.println("2 redirect to: " + redirectURL);

            redirectResponse.sendRedirect(request.getContextPath());

            return null;
        }

        /*String redirectURL = request.getContextPath();

        if (AuthenticationUtil.isInterupptedRequest(objectModel))
        {
            // Resume the request and set the redirect target URL to
            // that of the originally interrupted request.
            redirectURL += AuthenticationUtil.resumeInterruptedRequest(objectModel);
        }
        else
        {
            // Otherwise direct the user to the specified 'loginredirect' page (or homepage by default)
            String loginRedirect = ConfigurationManager.getProperty("xmlui.user.loginredirect");
            redirectURL += (loginRedirect != null) ? loginRedirect.trim() : "/";
        }

        System.out.println("save redirect: " + redirectURL);*/
        //session.setAttribute("resumeURL", redirectURL);

        // redirect to oauth authorization process
        AuthorizationCodeRequestUrl authorizationUrl = flow.newAuthorizationUrl().setRedirectUri(ConfigurationManager.getProperty("dspace.baseUrl")
                + request.getContextPath() + "/oauth-login");

        System.out.println("redirect to code request: " + authorizationUrl);
        final HttpServletResponse httpResponse = (HttpServletResponse) objectModel.get(HttpEnvironment.HTTP_RESPONSE_OBJECT);
        httpResponse.sendRedirect(authorizationUrl.toString());

        return null;
    }
}

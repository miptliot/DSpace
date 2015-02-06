/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate;

import org.apache.log4j.Logger;
import org.dspace.core.Context;
import org.dspace.core.LogManager;
import org.dspace.eperson.EPerson;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.SQLException;

/**
 * Authorize user through oauth mechanism
 *
 * @version $Revision$
 * @author Artur Komarov
 */
public class OAuthAuthentication implements AuthenticationMethod {
    private static Logger log = Logger.getLogger(OAuthAuthentication.class);

    public boolean canSelfRegister(Context context,
                                   HttpServletRequest request,
                                   String email)
            throws SQLException
    {
        return false;
    }

    public int authenticate(Context context,
                            String netid,
                            String password,
                            String realm,
                            HttpServletRequest request)
            throws SQLException {
        log.info(LogManager.getHeader(context, "auth", "attempting trivial auth of user=" + netid));

        // just say SUCCESS at the end
        return SUCCESS;
    }

    public void initEPerson(Context context, HttpServletRequest request,
                            EPerson eperson)
            throws SQLException
    {
        // just need to be implemented
    }

    /**
     * Add authenticated users to the group defined in authentication-password.cfg by
     * the login.specialgroup key.
     */
    public int[] getSpecialGroups(Context context, HttpServletRequest request) {
        return new int[0];
    }

    /*
     * This is an explicit method.
     */
    public boolean isImplicit()
    {
        return false;
    }

    /**
     * Cannot change password trough OAuth2
     */
    public boolean allowSetPassword(Context context,
                                    HttpServletRequest request,
                                    String username)
            throws SQLException
    {
        return false;
    }

    public String loginPageURL(Context context,
                               HttpServletRequest request,
                               HttpServletResponse response)
    {
        return response.encodeRedirectURL(request.getContextPath() +
                "/oauth-login");
    }

    public String loginPageTitle(Context context)
    {
        return "org.dspace.eperson.OAuthAuthentication.title";
    }
}

package com.skym.shibboleth.idp.keyjuggling;

import java.io.IOException;
import java.security.Principal;
import java.util.Set;
import java.util.*;
import javax.servlet.http.HttpSession;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.UsernamePasswordCredential;

public class PasswordKeyExchangeLoginServlet extends HttpServlet{

/** Serial version UID. */
private static final long serialVersionUID = -572799841125956990L;

/** Class logger. */
private final Logger log = LoggerFactory.getLogger(PasswordKeyExchangeLoginServlet.class);

/** The authentication method returned to the authentication engine. */
private static String authenticationMethod;

/** Name of JAAS configuration used to authenticate users. */
private String jaasConfigName = "ShibUserPassAuth";

/** init-param which can be passed to the servlet to override the default JAAS config. */
private final String jaasInitParam = "jaasConfigName";

/** Login page name. */
private String loginPage = "login.jsp";

/** init-param which can be passed to the servlet to override the default login page. */
private final String loginPageInitParam = "loginPage";

/** Parameter name to indicate login failure. */
private final String failureParam = "loginFailed";

/** HTTP request parameter containing the user name. */
private final String usernameAttribute = "j_username";

/** HTTP request parameter containing the user's password. */
private final String passwordAttribute = "j_password";
	
private final String pakeServlet = "/Auth/PAKE";
	
	/** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
		
        if (getInitParameter(jaasInitParam) != null) {
            jaasConfigName = getInitParameter(jaasInitParam);
        }
		
        if (getInitParameter(loginPageInitParam) != null) {
            loginPage = getInitParameter(loginPageInitParam);
        }
        if (!loginPage.startsWith("/")) {
            loginPage = "/" + loginPage;
        }
        
        String method =
		DatatypeHelper.safeTrimOrNullString(config.getInitParameter(LoginHandler.AUTHENTICATION_METHOD_KEY));
        if (method != null) {
            authenticationMethod = method;
        } else {
            authenticationMethod = AuthnContext.PPT_AUTHN_CTX;
        }
    }
	protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException,IOException {
		
		HttpSession session = request.getSession();
		
		String username = request.getParameter(usernameAttribute);
        String password = request.getParameter(passwordAttribute);
		if(session.getAttribute("PAKEAuth") == null){
		if (username == null || password == null) {
			redirectToLoginPage(request, response);
			return;
		}
		}
		try {
			if(session.getAttribute("PAKEAuth") == null && username != null && password != null){
			authenticateUser(request, username, password);
			}else if(session.getAttribute("PAKEAuth") == "OK"){
				HashMap map = (HashMap)session.getAttribute("payload");
				authenticate(request,map);
			}
			AuthenticationEngine.returnToAuthenticationEngine(request, response);
		} catch (LoginException e) {
			request.setAttribute(failureParam, "true");
			request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, new AuthenticationException(e));
			redirectToLoginPage(request, response);
		}
	}
	//ユーザログインのページへ遷移
	protected void redirectToLoginPage(HttpServletRequest request, HttpServletResponse response){
		
		StringBuilder actionUrlBuilder = new StringBuilder();
        if(!"".equals(request.getContextPath())){
            actionUrlBuilder.append(request.getContextPath());
        }
        actionUrlBuilder.append(request.getServletPath());
        
        request.setAttribute("actionUrl", actionUrlBuilder.toString());
		
        try {
				//response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			response.setHeader("WWW-Authentication","PAKE realm=\"Authentication PAKE Test \"");
            request.getRequestDispatcher(loginPage).forward(request, response);
            log.debug("Redirecting to login page {}", loginPage);
        } catch (IOException ex) {
            log.error("Unable to redirect to login page.", ex);
        } catch (ServletException ex) {
            log.error("Unable to redirect to login page.", ex);
        }		
	}
	
	/**
     * Authenticate a username and password against JAAS. If authentication succeeds the name of the first principal, or
     * the username if that is empty, and the subject are placed into the request in their respective attributes.
     * 
     * @param request current authentication request
     * @param username the principal name of the user to be authenticated
     * @param password the password of the user to be authenticated
     * 
     * @throws LoginException thrown if there is a problem authenticating the user
     */
    protected void authenticateUser(HttpServletRequest request, String username, String password) throws LoginException {
        try {
            log.debug("Attempting to authenticate user {}", username);
			SimpleCallbackHandler cbh = new SimpleCallbackHandler(username,password);
            javax.security.auth.login.LoginContext jaasLoginCtx = new javax.security.auth.login.LoginContext(jaasConfigName, cbh);
            jaasLoginCtx.login();
            log.debug("Successfully authenticated user {}", username);
			
            Subject loginSubject = jaasLoginCtx.getSubject();
			
            Set<Principal> principals = loginSubject.getPrincipals();
            principals.add(new UsernamePrincipal(username));
			
            Set<Object> publicCredentials = loginSubject.getPublicCredentials();
			
            Set<Object> privateCredentials = loginSubject.getPrivateCredentials();
            privateCredentials.add(new UsernamePasswordCredential(username,password));
			
            Subject userSubject = new Subject(false, principals, publicCredentials, privateCredentials);
            request.setAttribute(LoginHandler.SUBJECT_KEY, userSubject);
            request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authenticationMethod);
        } catch (LoginException e) {
            log.debug("User authentication for " + username + " failed", e);
            throw e;
        } catch (Throwable e) {
            log.debug("User authentication for " + username + " failed", e);
            throw new LoginException("unknown authentication error");
        }
    }
	protected void authenticate(HttpServletRequest request, HashMap map){
			//ユーザ名
		String user = (String)map.get("userID");
			//ユーザのsubjectを設定しない事例の確認
			//設定しない場合：
			//1:subjectそのものを生成しない場合
			//認証通過せずエラーメッセージ
		
			//2:空subjectを生成する場合
			//LoginHandler.SUBJECT_KEYに対して，subjectとauthenticationMethodの設定を行う場合
			//1度のアクセスではエラー表示されるが，別ブラウザを開いてアクセスすると認証処理に対して通過出来てしまう
			//問題な気がする
			//どうするか考えなければ
		Subject userSubject = new Subject();
		userSubject.getPrincipals().add(new UsernamePrincipal(user));
		request.setAttribute(LoginHandler.SUBJECT_KEY,userSubject);
		request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY,authenticationMethod);
		
	}
	/**
     * A callback handler that provides static name and password data to a JAAS loging process.
     * 
     * This handler only supports {@link NameCallback} and {@link PasswordCallback}.
     */
    protected class SimpleCallbackHandler implements CallbackHandler {
		
        /** Name of the user. */
        private String uname;
		
        /** User's password. */
        private String pass;
		
        /**
         * Constructor.
         * 
         * @param username The username
         * @param password The password
         */
        public SimpleCallbackHandler(String username, String password) {
            uname = username;
            pass = password;
        }
		
        /**
         * Handle a callback.
         * 
         * @param callbacks The list of callbacks to process.
         * 
         * @throws UnsupportedCallbackException If callbacks has a callback other than {@link NameCallback} or
         *             {@link PasswordCallback}.
         */
        public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {
			
            if (callbacks == null || callbacks.length == 0) {
                return;
            }
			
            for (Callback cb : callbacks) {
                if (cb instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) cb;
                    ncb.setName(uname);
                } else if (cb instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) cb;
                    pcb.setPassword(pass.toCharArray());
                }
            }
        }
    }
	
}
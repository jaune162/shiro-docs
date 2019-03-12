# Shiro运行原理--登录处理（2）

---

# executeLogin做了什么？

这里我们就会看到`SecurityManager`是如何在Shiro中大放异彩的。我们先从前面的一段配置，作为本章的开端。
```java
/**
 * 凭证管理
 */
@Bean
public Realm realm() {
    SimpleAccountRealm accountRealm = new SimpleAccountRealm();
    accountRealm.addAccount("user1", "123456");
    accountRealm.addAccount("admin", "123456", "admin");
    return accountRealm;
}

/**
 * 处理用户登录、注销、权限认证等核心业务
 */
@Bean
public DefaultWebSecurityManager securityManager(
        @Qualifier("realm") Realm realm,
        @Qualifier("sessionManager") SessionManager sessionManager) {
    DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
    securityManager.setSessionManager(sessionManager);
    securityManager.setRealm(realm);
    return securityManager;
}
```
请记住这段配置，然后接着看`executeLogin`的源码。
```java
// org.apache.shiro.web.filter.authc.AuthenticatingFilter#executeLogin

protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
    AuthenticationToken token = createToken(request, response);
    if (token == null) {
        String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                "must be created in order to execute a login attempt.";
        throw new IllegalStateException(msg);
    }
    try {
        Subject subject = getSubject(request, response);
        subject.login(token);
        return onLoginSuccess(token, subject, request, response);
    } catch (AuthenticationException e) {
        return onLoginFailure(token, e, request, response);
    }
}
```

依据这段代码我们一点一点展开。

# AuthenticationToken 

`AuthenticationToken`是登录凭证，它的子类有下面这些，在当前的配置中我们使用的是`UsernamePasswordToken`。这个是Shiro默认使用的Token，一般我们扩展也是继承自它，在它的基础上进行扩展。

![](https://images.jaune162.com/images/shiro/5/1.png)
下面我们来看`createToken`方法

```java
// org.apache.shiro.web.filter.authc.FormAuthenticationFilter
protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
    String username = getUsername(request);
    String password = getPassword(request);
    return createToken(username, password, request, response);
}

// org.apache.shiro.web.filter.authc.AuthenticatingFilter
protected abstract AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception;

protected AuthenticationToken createToken(String username, String password,
                                          ServletRequest request, ServletResponse response) {
    boolean rememberMe = isRememberMe(request);
    String host = getHost(request);
    return createToken(username, password, rememberMe, host);
}

protected AuthenticationToken createToken(String username, String password,
                                          boolean rememberMe, String host) {
    return new UsernamePasswordToken(username, password, rememberMe, host);
}
```
其实`createToken`是从request中获取了username和password以及rememberMe等字段内容，然后创建了一个`UsernamePasswordToken`实例。所以我们如果要实现验证码的功能的话首先需要扩展`AuthenticationToken`，创建一个Token类继承自`UsernamePasswordToken`，然后重写`createToken`方法。在下一个章节我们讲实现验证码的功能。

# subject.login
在web项目中默认创建的是`WebDelegatingSubject`，`WebDelegatingSubject`继承自`DelegatingSubject`，而`login`方法的代码就在`DelegatingSubject`中。先看login方法的核心代码。

```java
public void login(AuthenticationToken token) throws AuthenticationException {
    clearRunAsIdentitiesInternal();
    Subject subject = securityManager.login(this, token);
    // ...
}
```

从这里看到，调用的其实是`SecurityManager`中的login方法。

```java
// org.apache.shiro.mgt.DefaultSecurityManager#login
public Subject login(Subject subject, AuthenticationToken token) throws AuthenticationException {
    AuthenticationInfo info;
    try {
	    // 使用realm进行认证
        info = authenticate(token);
    } catch (AuthenticationException ae) {
        try {
            onFailedLogin(token, ae, subject);
        } catch (Exception e) {
            if (log.isInfoEnabled()) {
                log.info("onFailedLogin method threw an " +
                        "exception.  Logging and propagating original AuthenticationException.", e);
            }
        }
        throw ae; //propagate
    }
	// 创建Subject并保存登录信息到Session
    Subject loggedIn = createSubject(token, info, subject);
	// 处理rememberMe
    onSuccessfulLogin(token, info, loggedIn);

    return loggedIn;
}

//org.apache.shiro.mgt.AuthenticatingSecurityManager#authenticate
public AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {
    return this.authenticator.authenticate(token);
}
```

## authenticate方法
进入`login`方法后有调用`authenticate`方法生成`AuthenticationInfo`，`AuthenticationInfo`就是凭证信息，只有登录成功才会生成。

那么这个`authenticate`方法中的`authenticator`是什么呢？它就是`ModularRealmAuthenticator`，我们在前面提到过。首先我们看它的初始化过程。

```java
// org.apache.shiro.mgt.AuthenticatingSecurityManager
private Authenticator authenticator;

public AuthenticatingSecurityManager() {
    super();
    this.authenticator = new ModularRealmAuthenticator();
}
```
初始化过程非常简单，这时您可能会疑惑，初始化的时候并没有添加`Realm`啊，那我们创建的`Realm`是怎么跟它产生联系的呢？这时我们再回头看看我们的配置中的`securityManager.setRealm(realm);`。

先看`DefaultWebSecurityManager`的继承关系，这个继承关系有助于我们分析代码。

![](https://images.jaune162.com/images/shiro/5/2.png)


```java
// org.apache.shiro.mgt.RealmSecurityManager#setRealm
public void setRealm(Realm realm) {
    if (realm == null) {
        throw new IllegalArgumentException("Realm argument cannot be null");
    }
    Collection<Realm> realms = new ArrayList<Realm>(1);
    realms.add(realm);
    setRealms(realms);
}

public void setRealms(Collection<Realm> realms) {
    if (realms == null) {
        throw new IllegalArgumentException("Realms collection argument cannot be null.");
    }
    if (realms.isEmpty()) {
        throw new IllegalArgumentException("Realms collection argument cannot be empty.");
    }
    this.realms = realms;
    afterRealmsSet();
}

protected void afterRealmsSet() {
    applyCacheManagerToRealms();
    applyEventBusToRealms();
}
```
从上面的代码中看到，在配置了`Realm`后调用了一个`afterRealmsSet`方法。而`AuthenticatingSecurityManager`类重写了这个方法。
```java
protected void afterRealmsSet() {
    super.afterRealmsSet();
    if (this.authorizer instanceof ModularRealmAuthorizer) {
        ((ModularRealmAuthorizer) this.authorizer).setRealms(getRealms());
    }
}
```
从这里就可以看出，当我们配置了`Realm`后，Shiro向`ModularRealmAuthorizer`添加了我们配置的`Realm`。
> `Authorizer`是可以自定义的。如果自定义的`Authorizer`继承自`ModularRealmAuthorizer`，那么在配置的时候，`setAuthenticator`应该在`setRealm`或`setRealms`之前。因为这样才能确保`Realm`被添加到了自定义的`Authorizer`中。

知道了`ModularRealmAuthenticator`中的`Realm`是怎么来的，那么这是我们继续看它的`authenticate`方法。

```java
// org.apache.shiro.authc.AbstractAuthenticator#authenticate
public final AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {

    // ...

    AuthenticationInfo info;
    try {
        info = doAuthenticate(token);
        if (info == null) {
            String msg = "No account information found for authentication token [" + token + "] by this " +
                    "Authenticator instance.  Please check that it is configured correctly.";
            throw new AuthenticationException(msg);
        }
    } catch (Throwable t) {
        // ...
    }
    return info;
}

// org.apache.shiro.authc.pam.ModularRealmAuthenticator#doAuthenticate
protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
    assertRealmsConfigured();
    Collection<Realm> realms = getRealms();
    if (realms.size() == 1) {
        return doSingleRealmAuthentication(realms.iterator().next(), authenticationToken);
    } else {
        return doMultiRealmAuthentication(realms, authenticationToken);
    }
}
```

而无论是`doSingleRealmAuthentication`还是`doMultiRealmAuthentication`都是调用了`realm.getAuthenticationInfo(token)`方法。所以在这里`Realm`的`getAuthenticationInfo`是认证的核心方法。接着我们看`getAuthenticationInfo`方法。

```java
// org.apache.shiro.realm.AuthenticatingRealm#getAuthenticationInfo
// 首先从缓存中获取认证信息，如果缓存中没有则调用doGetAuthenticationInfo方法获取认证信息，然后再放到缓存中。
public final AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

    AuthenticationInfo info = getCachedAuthenticationInfo(token);
    if (info == null) {
        //otherwise not cached, perform the lookup:
        info = doGetAuthenticationInfo(token);
        log.debug("Looked up AuthenticationInfo [{}] from doGetAuthenticationInfo", info);
        if (token != null && info != null) {
            cacheAuthenticationInfoIfPossible(token, info);
        }
    } else {
        log.debug("Using cached authentication info [{}] to perform credentials matching.", info);
    }

    if (info != null) {
        assertCredentialsMatch(token, info);
    } else {
        log.debug("No AuthenticationInfo found for submitted AuthenticationToken [{}].  Returning null.", token);
    }

    return info;
}

// org.apache.shiro.realm.SimpleAccountRealm#doGetAuthenticationInfo
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    UsernamePasswordToken upToken = (UsernamePasswordToken) token;
    SimpleAccount account = getUser(upToken.getUsername());

    if (account != null) {

        if (account.isLocked()) {
            throw new LockedAccountException("Account [" + account + "] is locked.");
        }
        if (account.isCredentialsExpired()) {
            String msg = "The credentials for account [" + account + "] are expired";
            throw new ExpiredCredentialsException(msg);
        }

    }

    return account;
}
```
## 密码匹配器CredentialsMatcher
`doGetAuthenticationInfo`方法只负责查找用户，验证用户状态，但是不负责验证用户密码！，这点一定要注意。验证用户密码的方法在`getAuthenticationInfo`中调用`assertCredentialsMatch`方法实现的。如下
```java
if (info != null) {
    assertCredentialsMatch(token, info);
} else {
    log.debug("No AuthenticationInfo found for submitted AuthenticationToken [{}].  Returning null.", token);
}
```

```java
protected void assertCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) throws AuthenticationException {
    CredentialsMatcher cm = getCredentialsMatcher();
    if (cm != null) {
        if (!cm.doCredentialsMatch(token, info)) {
            //not successful - throw an exception to indicate this:
            String msg = "Submitted credentials for token [" + token + "] did not match the expected credentials.";
            throw new IncorrectCredentialsException(msg);
        }
    } else {
        throw new AuthenticationException("A CredentialsMatcher must be configured in order to verify " +
                "credentials during authentication.  If you do not wish for credentials to be examined, you " +
                "can configure an " + AllowAllCredentialsMatcher.class.getName() + " instance.");
    }
}
```
默认使用的是`SimpleCredentialsMatcher`，因为我们没有在`Realm`中配置`CredentialsMatcher`。如果我们想要使用MD5验证密码，则只需要写一个MD5匹配器，并实现`CredentialsMatcher`接口，并配置到`Realm`中即可。

```java
// CredentialsMatcher的接口定义。
boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info);
```
在验证密码成功后，返回`AuthenticationInfo`，即认证信息。
## 注意事项
 **验证码的匹配要写到CredentialsMatcher中吗？**
> 从接口定义中可以看出，`CredentialsMatcher`是可以对Token中的其他信息进行验证的，而不仅仅是密码。那么我们到底要不要在`CredentialsMatcher`校验验证码呢？这里推荐大家不要在这里校验。从`AuthenticationInfo`中单独提供的获取密码的接口`Object getCredentials();`就可以看出来，`CredentialsMatcher`应该是密码验证器，而不应该在此处校验其他内容。而验证码的校验可以放在`doGetAuthenticationInfo`方法中，在获取用户信息之前校验，作为校验用户的前置条件，如果发生错误则抛出`AuthenticationException`异常（一般自定义一个继承自`AuthenticationException`的验证码校验失败异常）。

**验证码的错误匹配的错误使用方式**
> 有的文章中是自定义了一个filter继承自`FormAuthenticationFilter`，然后重写`executeLogin`方法，在`executeLogin`中校验的验证码。这种做法是错误的。Why?

```java
// org.apache.shiro.web.filter.authc.AuthenticatingFilter#executeLogin
protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
    AuthenticationToken token = createToken(request, response);
    if (token == null) {
        String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                "must be created in order to execute a login attempt.";
        throw new IllegalStateException(msg);
    }
    try {
        Subject subject = getSubject(request, response);
        subject.login(token);
        return onLoginSuccess(token, subject, request, response);
    } catch (AuthenticationException e) {
        return onLoginFailure(token, e, request, response);
    }
}
```
重写只能这样写
```java

// 假设这是校验验证码的逻辑
private void checkCaptcha(AuthenticationToken token) throw AuthenticationException { /* ... */ }

// 方法一
protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
    AuthenticationToken token = createToken(request, response);
    if (token == null) {
        String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                "must be created in order to execute a login attempt.";
        throw new IllegalStateException(msg);
    }
    try {
	    checkCaptcha(token); // 代码复制一遍，然后验证的逻辑加到这里。
        Subject subject = getSubject(request, response);
        subject.login(token);
        return onLoginSuccess(token, subject, request, response);
    } catch (AuthenticationException e) {
        return onLoginFailure(token, e, request, response);
    }
}

// 方法二
protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
	AuthenticationToken token = createToken(request, response);
	if (token == null) {
        String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                "must be created in order to execute a login attempt.";
        throw new IllegalStateException(msg);
    }
    try {
	    checkCaptcha(token); // 代码复制一遍，然后验证的逻辑加到这里。
        return super.executeLogin(request, response);
    } catch (AuthenticationException e) {
        return onLoginFailure(token, e, request, response);
    }
    
}
```
如果我们要重写`executeLogin`会出现很多重复代码。可见这种扩展方式并不优雅，`executeLogin`并不适合这样扩展。所以在`Realm`中的`doGetAuthenticationInfo`是比较合理的。

## createSubject方法
让我们回到`org.apache.shiro.mgt.DefaultSecurityManager#login`。`AuthenticationInfo`生成后会重新生成`Subject`。`createSubject`的方法的调用链如下：

![](https://images.jaune162.com/images/shiro/5/3.png)

这里的`createSubject`主要做了两件事，一件就是创建`subject`，另外一件就是将`subject`保存到session中。

这里着重看`org.apache.shiro.web.mgt.DefaultWebSubjectFactory#createSubject`和`org.apache.shiro.mgt.DefaultSubjectDAO#saveToSession`。

```java
// org.apache.shiro.mgt.DefaultSecurityManager#createSubject(token, info, subject)
protected Subject createSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing) {
    SubjectContext context = createSubjectContext();
    // 设置是否认证成功
    context.setAuthenticated(true);
    // 设置Token
    context.setAuthenticationToken(token);
    // 此处将AuthenticationInfo添加到subjectContext中。
    context.setAuthenticationInfo(info);
    if (existing != null) {
        context.setSubject(existing);
    }
    return createSubject(context);
}

// org.apache.shiro.web.mgt.DefaultWebSubjectFactory#createSubject
public Subject createSubject(SubjectContext context) {
    if (!(context instanceof WebSubjectContext)) {
        return super.createSubject(context);
    }
    WebSubjectContext wsc = (WebSubjectContext) context;
    SecurityManager securityManager = wsc.resolveSecurityManager();
    Session session = wsc.resolveSession();
    boolean sessionEnabled = wsc.isSessionCreationEnabled();
    // 实际是从上面设置的AuthenticationInfo中获取的PrincipalCollection。
    PrincipalCollection principals = wsc.resolvePrincipals();
    boolean authenticated = wsc.resolveAuthenticated();
    String host = wsc.resolveHost();
    ServletRequest request = wsc.resolveServletRequest();
    ServletResponse response = wsc.resolveServletResponse();
	// 这里是新创建了一个Subject
    return new WebDelegatingSubject(principals, authenticated, host, session, sessionEnabled,
            request, response, securityManager);
}
```
由此可见`AuthenticationInfo`中存的是`principals`是什么内容，那么`Subject`中存的就是什么内容。在`SimpleAccountRealm`中`principals`设置的是username，所以我们通过`subject.getPrincipal()`方法获取到的就是username。如果我们需要保存User Bean信息，只需要重写`doGetAuthenticationInfo`方法，并构建一个`SimpleAuthenticationInfo`，将User Bean作为`principals`参数的值传进去即可。在后面的实践中会讲到。

```java
public SimpleAuthenticationInfo(Object principal, Object credentials, String realmName) {
    this.principals = new SimplePrincipalCollection(principal, realmName);
    this.credentials = credentials;
}
```

下面看`saveToSession`方法。
```java
protected void saveToSession(Subject subject) {
    mergePrincipals(subject);
    mergeAuthenticationState(subject);
}
```
`mergePrincipals`将`principals`信息保存到Session中，而`mergeAuthenticationState`将认证状态保存到session中。

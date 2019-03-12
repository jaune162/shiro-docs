# 类Session的无状态权限控制

---

前文中已经讲过主要的点和流程，那么我们思考下，要实现这样一种机制，我们需要做什么改动？

> 这里为了简化去掉了验证码及登录错误次数的限制等。在无状态服务中这些功能需要借助缓存和客户端地址或客户端设备号，实现难度不大，主要流程与前文提及的类似，所以不再赘述。

我们先来思考下面几个问题！
>**如何维护Token的有效期？**

如果我们把有效期放到Token中，那么这个有效期就是不可改变的，因为如果Token改变，那么就意味着前端需要不停的去维护新的Token，这肯定不是我们想要的。
> **如何禁用Session？**

禁用session的最主要的目的就是为了让开发人员不在使用session，因为如果开发人员仍然使用session来存储信息，那么将会导致十分严重的业务问题。禁用session后开发人员一旦使用session将会直接抛出异常，程序无法运行。

> **在哪里创建Token及如何将Token返回给客户端？**

在原来的方式中我们返回的是一个页面，而这里要返回的是`json`数据，因为前端要接收这串`json`数据并处理，而不是一个页面。

> **如何确保`SecurityUtils.getSubject()`有效？**

在程序中会有很多地方使用到`SecurityUtils.getSubject()`来获取用户信息，如果项目的接口一开始就是按照无状态服务的标准设计的，可能不会有很大的问题，但是如果是后来改造的呢？而且Shiro的过滤器中的`isAccessAllow`方法中也使用了`SecurityUtils.getSubject()`来验证登录状态和用户权限。

> 以上的几个问题将在下文中得到解决。大量代码袭来，请做好心理准备！！！！

# Token管理
先解决第一个问题，这里使用redis维护Token的有效期，在Token中设置一个`jwtId`，以`jwtId`为桥梁联系Token和缓存，缓存中村一个以`jwtId`为key的数据，设置有效期，如果过期这个`jwtId`将不存，所以可以通过判断缓存中是否有`jwtId`来确定Token是否过期。

redis缓存的操作使用是`spring-data-redis`

```java
// JwtTokenHash.java
/**
 * token 缓存信息
 *
 * @author jaune
 * @since 1.0.0
 */
@RedisHash("session.token")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtTokenHash {

    @Id
    private String id; // 缓存的Key

    private String userId; // 用户ID，可选

    @TimeToLive(unit = TimeUnit.MINUTES)
    private Long ttl; // 过期时间
}

// JwtTokenHashRedisRepository.java
public interface JwtTokenHashRedisRepository extends CrudRepository<JwtTokenHash, String> {
}

// JwtTokenManager.java
public interface JwtTokenManager {

    /**
     * 创建Token
     * @param sysUser 用户信息
     */
    String createToken(SysUser sysUser);

    /**
     * 创建Token
     * @param jwtId JWT ID
     * @param sysUser 用户信息
     */
    String createToken(String jwtId, SysUser sysUser);

    /**
     * 刷新Token，重置缓存有效期
     * @param token Token
     */
    void refreshToken(String token);

    /**
     * 删除Token
     * @param token Token
     */
    void deleteToken(String token);

    /**
     * 检查Token是否有效
     */
    boolean checkToken(String token);

    /**
     * 从Token中获取用户信息
     */
    SysUser resolve(String token);
}

// JwtTokenManagerImpl.java 具体实现
Component
public class JwtTokenManagerImpl implements JwtTokenManager {

    @Autowired
    private JwtTokenHashRedisRepository redisRepository;

    private String secret = "codestd.com"; // 可以随意设置，越长越不容易破解

    @Override
    public String createToken(SysUser sysUser) {
        return this.createToken(uuid(), sysUser);
    }

    @Override
    public String createToken(String jwtId, SysUser sysUser) {
	    // 使用用户ID和用户名生成Token，在Token中保存一个jwtId，并且以此作为缓存的key，保存到redis中，并设置缓存时间为30分钟。
        Algorithm algorithm = Algorithm.HMAC256(this.secret);
        String token = JWT.create()
                .withIssuer("CODESTD")
                .withSubject(sysUser.getUsername())
                .withIssuedAt(new Date())
                .withKeyId(sysUser.getUserId())
                .withJWTId(jwtId)
                .sign(algorithm);
        this.redisRepository.save(new JwtTokenHash(jwtId, sysUser.getUserId(), 30L));
        return token;
    }

    @Override
    public void refreshToken(String token) {
        DecodedJWT jwt = this.getJwt(token);
        this.redisRepository.save(new JwtTokenHash(jwt.getId(), jwt.getKeyId(), 30L));
    }

    @Override
    public void deleteToken(String token) {
        try {
            DecodedJWT jwt = this.getJwt(token);
            String jwtId = jwt.getId();
            this.redisRepository.deleteById(jwtId);
        } catch (JWTVerificationException ex) {
            // ignore
        }

    }

    @Override
    public boolean checkToken(String token) {
        if (!StringUtils.hasText(token)) {
            return false;
        }
        try {
            DecodedJWT jwt = this.getJwt(token);
            String jwtId = jwt.getId();
            Optional<JwtTokenHash> optional = this.redisRepository.findById(jwtId);
            return optional.isPresent();
        } catch (JWTVerificationException ex) {
            return false;
        }
    }

    @Override
    public SysUser resolve(String token) {
        if (this.checkToken(token)) {
            DecodedJWT jwt = this.getJwt(token);
            SysUser user = new SysUser();
            user.setUserId(jwt.getKeyId());
            user.setUsername(jwt.getSubject());
            return user;
        }
        return null;
    }

    private DecodedJWT getJwt(String token) {
        Algorithm algorithm = Algorithm.HMAC256(this.secret);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("CODESTD")
                .build(); //Reusable verifier instance
        return verifier.verify(token);
    }


    private String uuid() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString().replace("-", "");
    }

}
```

在这个类中我们提供了创建、刷新、删除、解析四个方法，基本上已经够我们使用了。

# 禁用Session
禁用Session在shiro文档中并没有给出相应的方法，所以这里是根据报错信息，已经对源码的阅读找到的一些地方，请大家参考。

1、SubjectDao，其中的`save`方法使用了Session。
```java
public Subject save(Subject subject) {
    if (isSessionStorageEnabled(subject)) {
        saveToSession(subject);
    } else {
        log.trace("Session storage of subject state for Subject [{}] has been disabled: identity and " +
                "authentication state are expected to be initialized on every request or invocation.", subject);
    }

    return subject;
}
```
这里的SessionStorage就是`DefaultSessionStorageEvaluator`，其中有一个`sessionStorageEnabled`属性，`isSessionStorageEnabled`方法就是判断的这个属性。所以禁用这里的Session的方法如下
```java
// 这是securityManager的配置
DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
DefaultSessionStorageEvaluator sessionStorageEvaluator = new DefaultSessionStorageEvaluator();
sessionStorageEvaluator.setSessionStorageEnabled(false);
subjectDAO.setSessionStorageEvaluator(sessionStorageEvaluator);
securityManager.setSubjectDAO(subjectDAO);
```

2、SessionManager的定时检查功能
```java
@Bean
public DefaultWebSessionManager sessionManager() {
    DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
    sessionManager.setSessionValidationSchedulerEnabled(false);
    return sessionManager;
}
```
这里的意思就是禁用Session检查的功能，默认是开启的。shiro会定时检查`SessionManager`中Session的状态。

3、`SubjectFactory.createSubject`

```java
@Override
public Subject createSubject(SubjectContext context) {
    context.setSessionCreationEnabled(false);
    // ...
}
```
创建一个`SubjectFactory`集成自`DefaultWebSubjectFactory`。然后重写`createSubject`方法，在这里为`SubjectContext`设置禁用Session。

4、`PathMatchingFilter`
Shiro中几乎所有的权限验证的过滤器都继承自它，其中有一个`saveRequestAndRedirectToLogin`调用了`saveRequest`方法，在这里使用了session。而这个方法是`onAccessDenied`调用的，所以在要重写`onAccessDenied`方法。所有在用的`filter`的`onAccessDenied`方法都需要重写。


# 创建Token及权限不足的处理
这是一个工具类
```java
public final class ResponseUtils {

    // 阻止使用new
    private ResponseUtils() {
    }

    public static void printResponseBean(ServletResponse servletResponse, ResponseBean responseBean) {
        HttpServletResponse response = WebUtils.toHttp(servletResponse);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        try {
            response.getWriter().print(responseBean.asJson());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void printAccessDeniedError(ServletResponse response) {
        ResponseBean responseBean = ResponseBean.builder()
                .success(false)
                .status(401)
                .message("权限不足")
                .build();

        printResponseBean(response, responseBean);
    }
}
```
登录过滤器
```java
public class StatelessAuthenticationFilter extends FormAuthenticationFilter {

    private JwtTokenManager tokenManager;

    public JwtTokenManager getTokenManager() {
        return tokenManager;
    }

    public void setTokenManager(JwtTokenManager tokenManager) {
        this.tokenManager = tokenManager;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        if (isLoginRequest(request, response)) {
            if (isLoginSubmission(request, response)) {
                return executeLogin(request, response);
            }
        }
        // 这里不需要跳转了，直接返回错误信息即可。
        ResponseUtils.printAccessDeniedError(response);
        // 阻止过滤器继续执行
        return false;
    }


    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
        JwtTokenManager jwtTokenManager = this.getTokenManager();
        SysUser user = (SysUser) subject.getPrincipals().getPrimaryPrincipal();
        String jwtToken = jwtTokenManager.createToken(user);
        ResponseUtils.printResponseBean(response, ResponseBean.mapBuilder()
                .add("accessToken", jwtToken)
                .success(true).status(200).build());
        // 登录成功，阻止过滤器链继续执行，并返回Token。
        return false;
    }

}
```
在`onLoginSuccess`中创建Token并返回到前台，这里可以直接使用`response`输出数据。

> **注意**
> `RolesAuthorizationFilter`和`PermissionsAuthorizationFilter`中的`onAccessDenied`方法同样需要重写，因为在这两个类中，这个方法是跳转到登录页面的，而不是输出错误信息。这里省略这部分，详细可查看本文最后给出的源码地址。

# 登录失败的处理
登录失败会回到`LoginController`的`login`方法。我们需要将这个方法改为，将错误信息以json的形式返回。
```java
@PostMapping("/login")
public ResponseBean login(HttpServletRequest request) {
    String errorClassName = (String)request.getAttribute(
            FormAuthenticationFilter.DEFAULT_ERROR_KEY_ATTRIBUTE_NAME);

    if (errorClassName != null) {
        errorClassName = errorClassName.substring(errorClassName.lastIndexOf(".") + 1);
    } else {
        return new ResponseBean();
    }
    String errorMessage;
    switch (errorClassName) {
        case "IncorrectCredentialsException":
            errorMessage = "密码错误！";
            break;
        case "UnknownAccountException":
            errorMessage = "用户名不存在！";
            break;
        case "DisabledAccountException":
            errorMessage = "账户已被禁用！";
            break;
        case "LockedAccountException":
            errorMessage = "账户已被锁定！";
            break;
        default:
            errorMessage = "登录失败！";
    }
    return ResponseBean.builder().success(false)
            .message(errorMessage)
            .build();
}
```

# 注销
```java
public class StatelessLogoutFilter extends LogoutFilter {
    
    private JwtTokenManager jwtTokenManager;

    public void setJwtTokenManager(JwtTokenManager jwtTokenManager) {
        this.jwtTokenManager = jwtTokenManager;
    }

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) {
        String token = WebUtils.toHttp(request).getHeader(StatelessWebSubjectFactory.AUTH_HEADER_NAME);
        if (StringUtils.hasText(token)) {
            this.jwtTokenManager.deleteToken(token);
        }
        ResponseUtils.printResponseBean(response, ResponseBean.builder()
                .success(true).status(200).message("注销成功").build());
        return false;
    }
}
```
这里的注销不再需要调用`subject.logout`因为这个方法是从Session中清空登录信息的，我们已经不使用Session了所以也不用从Session中清除什么数据。在这里只需要将Token从缓存中删除即可。

# 创建Suject
创建`StatelessWebSubjectFactory`类，集成自`DefaultWebSubjectFactory`	。重写`createSubject`方法。

```java
public class StatelessWebSubjectFactory extends DefaultWebSubjectFactory {

    public static final String AUTH_HEADER_NAME = "AUTHENTICATION";

    private JwtTokenManager jwtTokenManager;

    public void setJwtTokenManager(JwtTokenManager jwtTokenManager) {
        this.jwtTokenManager = jwtTokenManager;
    }

    @Override
    public Subject createSubject(SubjectContext context) {
        context.setSessionCreationEnabled(false);
        if (!(context instanceof WebSubjectContext)) {
            return super.createSubject(context);
        }
        WebSubjectContext wsc = (WebSubjectContext) context;

        HttpServletRequest request = WebUtils.toHttp(wsc.resolveServletRequest());
        String token = request.getHeader(AUTH_HEADER_NAME);
        if (this.jwtTokenManager.checkToken(token)) {
            SysUser user = this.jwtTokenManager.resolve(token);
            wsc.setAuthenticated(true);
            wsc.setPrincipals(new SimplePrincipalCollection(user, user.getUsername()));
            this.refreshToken(token);
        }
        return super.createSubject(context);
    }

    private void refreshToken(String token) {
        this.jwtTokenManager.refreshToken(token);
    }
}
```
每个请求都会经过这个方法，所以在这里刷新验证码是最合适不过的了。否则就需要新建一个过滤器来专门处理这件事情了。

> **这里简单的分析下我们为什么脱离了Session还可以使用`SecurityUtils.getSubject()`方法。**
>这是因为所有的请求都会经过`shiroFilter`的`doFilterInternal`而这个方法中又调用了`SubjectFactory.createSubject()`方法。原来的处理方式是在这个方法中从Session中读取用户信息和登录状态，而现在变成从HTTP请求头中读取用户信息和登录状态，所以对于Subject的创建是没有什么影响的。而Subject在创建好之后是放在`ThreadLocal`中的，我们并不是从Session中获取的Subject，也就是在后面的使用中没有用到Session，所以`SecurityUtils.getSubject()`可以正常使用。这里要注意的是`subject.getSession`是不可用的。


# 配置
这里只列出跟原来不一样的配置。其他配置仍然可以参考原来的配置。

首先删除`SessionListener`的配置，这个不需要了，也无法使用。

```java
@Bean
public StatelessWebSubjectFactory webSubjectFactory(
        @Qualifier("jwtTokenManagerImpl") JwtTokenManager jwtTokenManager) {
    StatelessWebSubjectFactory subjectFactory = new StatelessWebSubjectFactory();
    subjectFactory.setJwtTokenManager(jwtTokenManager);
    return subjectFactory;
}

@Bean
public DefaultWebSessionManager sessionManager() {
    DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
    sessionManager.setSessionValidationSchedulerEnabled(false);
    return sessionManager;
}

/**
 * 处理用户登录、注销、权限认证等核心业务
 */
@Bean
public DefaultWebSecurityManager securityManager(
        @Qualifier("webSubjectFactory") SubjectFactory subjectFactory,
        @Qualifier("realm") Realm realm,
        @Qualifier("sessionManager") SessionManager sessionManager) {
    DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
    securityManager.setSessionManager(sessionManager);
    securityManager.setRealm(realm);
    securityManager.setSubjectFactory(subjectFactory);

    DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
    DefaultSessionStorageEvaluator sessionStorageEvaluator = new DefaultSessionStorageEvaluator();
    sessionStorageEvaluator.setSessionStorageEnabled(false);
    subjectDAO.setSessionStorageEvaluator(sessionStorageEvaluator);
    securityManager.setSubjectDAO(subjectDAO);
    return securityManager;
}

/**
 * 登录过滤器
 */
@Bean
public StatelessAuthenticationFilter authenticationFilter(
        @Qualifier("jwtTokenManagerImpl") JwtTokenManager jwtTokenManager) {
    StatelessAuthenticationFilter statelessAuthenticationFilter = new StatelessAuthenticationFilter();
    statelessAuthenticationFilter.setTokenManager(jwtTokenManager);
    return statelessAuthenticationFilter;
}
@Bean
public StatelessLogoutFilter logoutFilter(
        @Qualifier("jwtTokenManagerImpl") JwtTokenManager jwtTokenManager) {
    StatelessLogoutFilter logoutFilter = new StatelessLogoutFilter();
    logoutFilter.setJwtTokenManager(jwtTokenManager);
    return logoutFilter;
}
```

完整代码请参考：<https://gitee.com/jaune/springboot-shiro-stateless/tree/V1.0.0>

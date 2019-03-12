# 免登陆的无状态权限控制

---

前文已经说到，这里采用`refreshToken`+`accessToken`的方式实现免登陆。

这个问题的难点在于如何让模拟Session的登录和这种免登陆这两种方式共存。Token的管理和登录认证随有类似的地方，但是还是不大相同的。那么下面我们一步一步实现这个麻烦的功能。

> 本文将着重讲解处理问题的方式，会省略掉很多不太重要的代码，如果哪位同学需要完整代码，请到文章的末尾找到本例的源码地址，然后在`gitee`中查看完整代码。另外这一章与前一章是有着紧密联系的，请阅读本章之前一定先阅读前一章。


# 维护refreshToken

```java
public interface MobileTokenManager {

    /**
     * 创建refreshToken
     * @param user 用户信息
     * @param type 设备类型，1-安卓,2-IOS
     * @return refreshToken
     */
    String createRefreshToken(SysUser user, String type);

    /**
     * 删除refreshToken，在本实例中一个用户只能在同一类设备中登录一次。
     * @param userId 用户ID
     * @param type 设备类型，1-安卓,2-IOS
     */
    void deleteRefreshToken(String userId, String type);

    /**
     * 从缓存中获取refreshToken
     * @param refreshToken token内容
     * @return Optional对象
     */
    Optional<RefreshToken> getRefreshToken(String refreshToken);
}
```
这里只列出接口信息，具体实现请参考源码。在本实例中没有维护refreshToken和accessToken的映射。所以如果用户同时登录两台同类型设备，不能立即将另外一个用户踢掉，只能等待`accessToken`失效之后另外一个用户才能失去访问权限。这一点大家请注意下，一定要结合自己的业务来处理token的访问权限。

# 处理JWT Token（accessToken）的差异
在web项目中的`accessToken`和移动端的`accessToken`是不一样的。web中的`accessToken`有效期是在缓存中维护，只要用户一直在使用，`accessToken`就不会失效。但是在移动端`accessToken`的有效期是固定的，超过有效期之后需要重新使用`refreshToken`获取一个新的`accessToken`。那么为了让两种`accessToken`的处理方式兼容，我们在创建`accessToken`的时候做一点手脚，给移动端的加上一个标记。当调用刷新token的方法时，检查`accessToken`中是否有这个标记，如果有则认为是移动端的Token就不做处理，如果没有就重置刷新时间。而移动端的`accessToken`也不再在缓存中维护过期时间。

```java
// com.codestd.security.shiro.jwt.JwtTokenManagerImpl

@Override
public String createTokenForMobile(SysUser sysUser) {
    Calendar calendar = Calendar.getInstance();
    calendar.setTime(new Date());
    calendar.add(Calendar.MINUTE, 30);

    Algorithm algorithm = Algorithm.HMAC256(this.secret);
    return JWT.create()
            .withIssuer("CODESTD")
            .withSubject(sysUser.getUsername())
            .withIssuedAt(new Date())
            .withKeyId(sysUser.getUserId())
            .withExpiresAt(calendar.getTime()) // 设置过期时间
            .withClaim("type", "MOBILE")
            .sign(algorithm);
}

@Override
public void refreshToken(String token) {
    try {
        DecodedJWT jwt = this.getJwt(token);
        if (this.isMobileToken(jwt)) {
            return;
        }
        this.redisRepository.save(new JwtTokenHash(jwt.getId(), jwt.getKeyId(), 30L));
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
        if (isMobileToken(jwt)) {
            return true;
        }
        String jwtId = jwt.getId();
        Optional<JwtTokenHash> optional = this.redisRepository.findById(jwtId);
        return optional.isPresent();
    } catch (JWTVerificationException ex) {
        return false;
    }
}
```

这里重点关注下`checkToken`方法，因为在移动端的Token中增加了过期时间所以在`getJwt`方法中调用`verifier.verify`的时候会检查是否过期，如果过期则抛出`JWTVerificationException`异常，如果没有过期则可以正常解析。而我们的移动端的Token是没有放在缓存中的，所以这里校验是否是移动端Token，如果是，就证明Token没有过期，所以可以直接返回`true`。

# AuthenticationToken创建
重写`StatelessAuthenticationFilter`中的`createToken`方法。

```java
// com.codestd.security.shiro.filter.StatelessAuthenticationFilter#createToken
/**
 * 这里根据type字段判断是否为移动端，实际项目中可以使用spring-mobile
 */
@Override
protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
    String refreshToken = request.getParameter("refreshToken");
    String type = request.getParameter("type");
    if (refreshToken != null && type != null) {
        return new StatelessToken(refreshToken, type);
    }
    if (type != null) {
        StatelessToken token = new StatelessToken(null, type);
        token.setUsername(getUsername(request));
        token.setPassword(getPassword(request).toCharArray());
        token.setHost(getHost(request));
        token.setRememberMe(isRememberMe(request));
        return token;
    }
    return super.createToken(request, response);
}
```

```java
// com.codestd.security.shiro.token.StatelessToken
public class StatelessToken extends UsernamePasswordToken {

    private String refreshToken;
    private String type;

	// ......
}
```
由于本实例只是一个`demo`所以这里处理的不严谨，仅仅是根据`type`字段来判断创建什么Token。在实际的项目中可以使用`spring-mobile`或获取request的`User-Agent`来根据客户端类型来创建Token。

这段代码的意思就是
- 如果有`type`和`refreshToken`说明使用`refreshToken`登录的，就创建`StatelessToken`，然后`Realm`根据`refreshToken`登录。
- 如果只有`type`，那么创建的`StatelessToken`中就要包含用户名和密码等信息。
- 如果没有`type`，就调用父类的`createToken`创建一个`UsernamePasswordToken`。

这里的两种Token是要交给两个`Realm`分别进行处理的。

# 两个Realm处理两种Token

首先让`DatabaseRealm`只处理`UsernamePasswordToken`，重写其`supports`方法。
```java
@Override
public boolean supports(AuthenticationToken token) {
    if (token instanceof StatelessToken) {
        return false;
    } else {
        return super.supports(token);
    }
}
```

然后抽离出来一个公共的方法，用于根据用户名获取用户信息并校验用户状态。

```java
protected SysUser getAndCheckUser(String username) {
    SysUser user = this.sysUserMapper.findByUsernameOrPhoneNumber(username);

    // 如果用户为空，则抛出用户不存在的异常
    if (user == null) {
        throw new UnknownAccountException();
    }

    // 判断用户状态
    if (UserState.LOCKED.is(user.getState())) {
        throw new LockedAccountException();
    } else if (UserState.DISABLED.is(user.getState())) {
        throw new DisabledAccountException();
    }
    return user;
}
```

创建`MobileRealm`并继承自`DatabaseRealm`用户处理移动端的登录。

```java
/**
 * 移动端登录
 *
 * @author jaune
 * @since 1.0.0
 */
public class MobileRealm extends DatabaseRealm {

    private MobileTokenManager mobileTokenManager;

    @Autowired
    private SysUserMapper sysUserMapper;

    public void setMobileTokenManager(MobileTokenManager mobileTokenManager) {
        this.mobileTokenManager = mobileTokenManager;
    }

    /**
     * 这里只处理StatelessToken
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof StatelessToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        StatelessToken statelessToken = (StatelessToken) token;
        // 判断是否有refreshToken，如果有使用refreshToken登录，如果没有就使用用户名密码登录。
        if (statelessToken.getRefreshToken() != null) {
            return this.loginByRefreshToken(statelessToken);
        } else {
            return this.loginByUsernameAndPassword(statelessToken);
        }
    }

    /**
     * 使用用户名密码登录
     */
    private AuthenticationInfo loginByUsernameAndPassword(StatelessToken statelessToken) {
        SysUser user = this.getAndCheckUser(statelessToken.getUsername());
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user, user.getPassword(), user.getUsername());
        this.clearCachedAuthorizationInfo(authenticationInfo.getPrincipals());
        return authenticationInfo;
    }

    /**
     * 使用refreshToken登录。从缓存中获取refreshToken，如果缓存中有，则证明refreshToken有效可以作为获取AccessToken的凭证。
     */
    private AuthenticationInfo loginByRefreshToken(StatelessToken statelessToken) {
        Optional<RefreshToken> optional =
                this.mobileTokenManager.getRefreshToken(statelessToken.getRefreshToken());
        if (optional.isPresent()) {
            // RefreshToken缓存的时候，缓存了用户ID
            String userId = optional.get().getUserId();
            SysUser user = this.sysUserMapper.selectByPrimaryKey(userId);
            this.checkUser(user); // 这里同样要检查用户状态
            // 密码可以设置为空（第二个参数），我们在后面密码验证的时候会做处理
            SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user, null, user.getUsername());
            this.clearCachedAuthorizationInfo(authenticationInfo.getPrincipals());
            return authenticationInfo;
        } else {
            return new SimpleAuthenticationInfo();
        }
    }
}
```

# 修改密码验证
用户名和密码登录的时候是需要验证密码的，但是使用refreshToken登录的时候是不需要验证密码的，而按照shiro的流程，是有专门的验证密码这一步的。所以我们就得在密码匹配器中做文章了。

```java
// com.codestd.security.shiro.matcher.Md5CredentialsMatcher
@Override
public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
    if (!this.needCheckPassword(token)) {
        return true;
    }
    String dbPassword = (String) info.getCredentials();
    UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
    String encryptPassword = DigestUtils.md5Hex(new String(usernamePasswordToken.getPassword()));
    return dbPassword.equals(encryptPassword);
}

/**
 * 首先验证是否为StatelessToken，然后在验证如果StatelessToken中的refreshToken不为空，则不需验证。
 */
private boolean needCheckPassword(AuthenticationToken token) {
    if (token instanceof StatelessToken) {
        return !StringUtils.hasText(((StatelessToken) token).getRefreshToken());
    }
    return true;
}
```

这里`needCheckPassword`来检查是否需要验证密码，如果不需要则直接返回`true`。

# 创建`refreshToken`和`accessToken`
仍然是在`StatelessAuthenticationFilter`中的`onLoginSuccess`方法中处理。
```java
@Override
protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
    if (token instanceof StatelessToken) {
        return refreshTokenLoginHandle(token, subject, response);
    } else {
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

/**
 * refreshToken登录流程。
 */
private boolean refreshTokenLoginHandle(AuthenticationToken token, Subject subject, ServletResponse response) {
    StatelessToken statelessToken = (StatelessToken) token;
    SysUser user = (SysUser) subject.getPrincipals().getPrimaryPrincipal();
    // 这里只要登录成功，就删除refreshToken并重新生成一个。注意这里是根据设备类型来删除的，也就是说同一个设备类型同一个用户只能有一个有效的refreshToken
    this.getMobileTokenManager().deleteRefreshToken(user.getUserId(), statelessToken.getType());
    
    // 创建refreshToken和accessToken并返回到前端
    String accessToken = this.getTokenManager().createTokenForMobile(user);
    String refreshToken = this.getMobileTokenManager().createRefreshToken(user, statelessToken.getType());
    ResponseUtils.printResponseBean(response, ResponseBean.mapBuilder()
            .add("accessToken", accessToken)
            .add("refreshToken", refreshToken)
            .success(true).status(200).build());
    // 登录成功，阻止过滤器链继续执行，并返回Token。
    return false;

}
```

# 配置

```java
/**
 * 凭证管理
 */
@Bean
public DatabaseRealm databaseRealm(/* ...  */) { // 这里有原来的realm重命名为databaseRealm
    // ... 
}

/**
 * StatelessToken 凭证管理
 */
@Bean
public MobileRealm mobileRealm(@Qualifier("ehCacheManager") CacheManager cacheManager,
                               @Qualifier("mobileTokenManagerImpl") MobileTokenManager mobileTokenManager,
                               @Qualifier("rolePermissionResolver") RolePermissionResolver rolePermissionResolver) {
    MobileRealm realm = new MobileRealm();
    realm.setCredentialsMatcher(new Md5CredentialsMatcher());
    realm.setCacheManager(cacheManager);
    realm.setAuthorizationCacheName("AuthorizationCache");
    realm.setAuthenticationCachingEnabled(false);
    realm.setAuthorizationCachingEnabled(true);
    realm.setRolePermissionResolver(rolePermissionResolver);
    realm.setMobileTokenManager(mobileTokenManager);
    return realm;
}

/**
 * 处理用户登录、注销、权限认证等核心业务
 */
@Bean
public DefaultWebSecurityManager securityManager(
        @Qualifier("webSubjectFactory") SubjectFactory subjectFactory,
        @Qualifier("databaseRealm") DatabaseRealm databaseRealm,
        @Qualifier("mobileRealm") MobileRealm mobileRealm,
        @Qualifier("sessionManager") SessionManager sessionManager) {
    DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
    securityManager.setSessionManager(sessionManager);

    List<Realm> realms = new ArrayList<>();
    realms.add(databaseRealm);
    realms.add(mobileRealm);
    securityManager.setRealms(realms); // 这里由原来的配置一个realm改为配置多个

    // ...
    return securityManager;
}

/**
 * 登录过滤器
 */
@Bean
public StatelessAuthenticationFilter authenticationFilter(
        @Qualifier("jwtTokenManagerImpl") JwtTokenManager jwtTokenManager,
        @Qualifier("mobileTokenManagerImpl") MobileTokenManager mobileTokenManager) {
    StatelessAuthenticationFilter statelessAuthenticationFilter = new StatelessAuthenticationFilter();
    statelessAuthenticationFilter.setTokenManager(jwtTokenManager);
    statelessAuthenticationFilter.setMobileTokenManager(mobileTokenManager);
    return statelessAuthenticationFilter;
}
```

配置完成之后重启即可测试。

登录成功之后会返回`refreshToken`和`accessToken`。
```java
{
    "success": true,
    "status": 200,
    "message": null,
    "data": {
        "accessToken": "eyJraWQiOiIxIiwidHlwIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhZG1pbiIsImlzcyI6IkNPREVTVEQiLCJpYXQiOjE1MzMwOTQxODYsImp0aSI6IjgyNTE5MWI1ZjkzOTRlYWY4YzVmNzY2ZjU1M2Y5MDM2In0.Wb80LHu7Gu0MFxRerwOofnijre42nuHRtom220QN31M",
        "refreshToken": "5a51711f24e64a9c966708a64d82ecf0"
    }
}
```
使用refreshToken登录可成功登录，再使用用过的`refreshToken`登录时不可登录。已经达到我们之前说的需求。

本实例源码：<https://gitee.com/jaune/springboot-shiro-stateless>

# 结语
本次教程到这里已结束。希望大家能从教程中学到各项配置的作用、shiro扩展的方式、能够理解shiro的工作原理并且学会阅读源码，以便用于应对在实际工作中千变万化的需求。

另外本教程中所有的源码并没有经过正式的测试，可能无法达到生产环境的使用标准。所以希望大家在使用的时候一定要把好测试关，**线上没有小问题**。

**最后感谢大家阅读本教程，谢谢关照！！！**


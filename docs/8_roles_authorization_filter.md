# 角色/权限拦截原理

---

![](https://images.jaune162.com/images/shiro/8/1.png)

这里以角色检查为例来介绍整个流程，其他类似。

# 1、`shiroFilter`根据地址获取处理资源的过滤器链
用户发起的请求到`shiroFilter`（也就是`SpringShiroFilter`）时，通过`FilterChainResolver`获取负责处理资源的过滤器链。
```java
protected void executeChain(ServletRequest request, ServletResponse response, FilterChain origChain)
        throws IOException, ServletException {
    FilterChain chain = getExecutionChain(request, response, origChain);
    chain.doFilter(request, response);
}
```

# 2、获取访问资源所需的角色
在负责处理资源的过滤器中`preHandle`方法（Shiro中处理权限的Filter都继承了`PathMatchingFilter`，所以这里的`preHandle`是`PathMatchingFilter`中的方法）中获取访问资源对应的权限或角色信息。
```java
protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {

    if (this.appliedPaths == null || this.appliedPaths.isEmpty()) {
        if (log.isTraceEnabled()) {
            log.trace("appliedPaths property is null or empty.  This Filter will passthrough immediately.");
        }
        return true;
    }

    for (String path : this.appliedPaths.keySet()) {
        if (pathsMatch(path, request)) {
            log.trace("Current requestURI matches pattern '{}'.  Determining filter chain execution...", path);
            Object config = this.appliedPaths.get(path);
            return isFilterChainContinued(request, response, path, config);
        }
    }
    return true;
}
```

`Object config = this.appliedPaths.get(path);`这句就是根据资源获取所需权限或资源的。`appliedPaths`中是这个过滤器负责处理的全部资源及权限或角色的映射，是在创建初始化时`set`进来的。

# 3、执行检查权限方法
随后Filter执行`isAccessAllowed`方法来判断是否允许访问。
```java
// org.apache.shiro.web.filter.authz.RolesAuthorizationFilter#isAccessAllowed
public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
x
    Subject subject = getSubject(request, response);
    String[] rolesArray = (String[]) mappedValue;

    if (rolesArray == null || rolesArray.length == 0) {
        //no roles specified, so nothing to check - allow access.
        return true;
    }

    Set<String> roles = CollectionUtils.asSet(rolesArray);
    return subject.hasAllRoles(roles);
}
```
在这里调用`subject.hasAllRoles`检查角色。而`subject.hasAllRoles`实际是调用的`securityManager.hasAllRoles`来进行角色检查的。

# 4、SecurityManager检查权限
SecurityManager调用`authorizer`的`hasAllRoles`方法检查用户是否有访问资源所需的角色。
```java
// org.apache.shiro.mgt.AuthorizingSecurityManager#hasAllRoles
public boolean hasAllRoles(PrincipalCollection principals, Collection<String> roleIdentifiers) {
    return this.authorizer.hasAllRoles(principals, roleIdentifiers);
}
```

而这里的`authorizer`就是`ModularRealmAuthorizer`。

```java
public boolean hasAllRoles(PrincipalCollection principals, Collection<String> roleIdentifiers) {
    assertRealmsConfigured(); // 检查Realm是否配置
    for (String roleIdentifier : roleIdentifiers) {
        if (!hasRole(principals, roleIdentifier)) {
            return false;
        }
    }
    return true;
}

public boolean hasRole(PrincipalCollection principals, String roleIdentifier) {
    assertRealmsConfigured(); // 检查Realm是否配置
    for (Realm realm : getRealms()) {
        if (!(realm instanceof Authorizer)) continue;
        if (((Authorizer) realm).hasRole(principals, roleIdentifier)) {
            return true;
        }
    }
    return false;
}
```
`SecurityManager`调用`ModularRealmAuthorizer`检查用户权限，而`ModularRealmAuthorizer`有调用`Authorizer`检查权限。
# 5、Authorizer获取权限或角色信息

`Authorizer`其实就是我们的`Realm`。
![](https://images.jaune162.com/images/shiro/8/2.png)
从图中可以看出`AuthorizingRealm`实现了`Authorizer`接口。那么在`AuthorizingRealm`中`hasRole`是怎么执行的呢？

```java
public boolean hasRole(PrincipalCollection principal, String roleIdentifier) {
    AuthorizationInfo info = getAuthorizationInfo(principal);
    return hasRole(roleIdentifier, info);
}

protected AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

    if (principals == null) {
        return null;
    }

    AuthorizationInfo info = null;
    // ...省略日志代码
    Cache<Object, AuthorizationInfo> cache = getAvailableAuthorizationCache();
    if (cache != null) {
        // ...省略日志代码
        Object key = getAuthorizationCacheKey(principals);
        info = cache.get(key);
        // ...省略日志代码
    }


    if (info == null) {
        // Call template method if the info was not found in a cache
        info = doGetAuthorizationInfo(principals);
        // If the info is not null and the cache has been created, then cache the authorization info.
        if (info != null && cache != null) {
            // ...省略日志代码
            Object key = getAuthorizationCacheKey(principals);
            cache.put(key, info);
        }
    }

    return info;
}
```
首先从缓存中获取`AuthorizationInfo`，如果缓存中没有则执行`doGetAuthorizationInfo`获取`AuthorizationInfo`。`doGetAuthorizationInfo`是一个抽象方法。需要在我们自己的`Realm`中实现。我们当前的配置是没有启用缓存的，也就是说每次调用`hasRole`都要调用`doGetAuthorizationInfo`获取`AuthorizationInfo`。这是很危险的，因为一般我们都是从数据库中获取用户的权限或角色信息的，如果不配置缓存数据库的压力将会非常大。

# 配置缓存

这里我们使用`shiro-ehcache`包中提供的`EhCacheManager`。
```java
Bean
public EhCacheManager ehCacheManager() {
    EhCacheManager ehCacheManager = new EhCacheManager();
    ehCacheManager.setCacheManagerConfigFile("classpath:ehcache.xml");
    return ehCacheManager;
}
```
ehcache.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<ehcache xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="http://ehcache.org/ehcache.xsd">

    <!-- 磁盘缓存位置 -->
    <diskStore path="java.io.tmpdir/ehcache"/>

    <!-- 默认缓存 -->
    <defaultCache
            maxEntriesLocalHeap="10000"
            eternal="false"
            timeToIdleSeconds="120"
            timeToLiveSeconds="120"
            maxEntriesLocalDisk="10000000"
            diskExpiryThreadIntervalSeconds="120"
            memoryStoreEvictionPolicy="LRU">
        <persistence strategy="localTempSwap"/>
    </defaultCache>

    <!-- AuthorizationCache缓存 -->
    <cache name="AuthorizationCache"
           maxElementsInMemory="0"
           eternal="true"
           overflowToDisk="true"
           memoryStoreEvictionPolicy="LRU"/>
</ehcache>
```

修改`realm`配置

```java
@Bean
public DatabaseRealm realm(@Qualifier("ehCacheManager") CacheManager cacheManager) {
    DatabaseRealm realm = new DatabaseRealm();
    realm.setCredentialsMatcher(new Md5CredentialsMatcher());
    realm.setCacheManager(cacheManager);
    // 这里的chacheName需要与ehcache.xml中配置的一致
    realm.setAuthorizationCacheName("AuthorizationCache");
    realm.setAuthenticationCachingEnabled(false); // 暂时不起用Authentication Cache
    realm.setAuthorizationCachingEnabled(true);
    return realm;
}
```
然后重写`getAuthorizationCacheKey`方法。改成以userId作为缓存的Key。
```java
@Override
protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
    if (principals != null && principals.getPrimaryPrincipal() != null) {
        SysUser user = (SysUser) principals.getPrimaryPrincipal();
        return user.getUserId();
    } else {
        return super.getAuthorizationCacheKey(principals);
    }
}
```

配置完之后就不会每次使用`hasRole`方法都调用`doGetAuthorizationInfo`获取`AuthorizationInfo`了。而且在`Logout`时会自动清除缓存数据。但是这样还存在为题，就是session失效时，或者我们直接关闭浏览器，这时候都不会自动清除缓存，这回导致再次登录的时候还是读取的缓存中的权限信息。目前没有找到完美的解决方法，有一种变通的方法就是在每次登录的时候都执行一次清除缓存的操作。

修改`DatabaseRealm`中的`doGetAuthenticationInfo`
```java
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    
    // ... 省略上面的代码，上面部分的代码不用动。

    SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user, user.getPassword(), user.getUsername());
    this.clearCachedAuthorizationInfo(authenticationInfo.getPrincipals());
    return authenticationInfo;
}
```

也就是在登录之前调用`clearCachedAuthorizationInfo`清除缓存的权限信息，这样每次登录成功之后都会再次获取权限信息。

这部分的实例源码参见：<https://gitee.com/jaune/spring-boot-shiro/tree/V2.0.2>

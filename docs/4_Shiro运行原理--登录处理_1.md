# Shiro运行原理--登录处理（1）

---

引用官方的结构图，通过这张结构图介绍Shiro的运行原理

> 本章及后续的几个章节会做大量的源码分析，在引用源码的时候我会增加源码所在类的注释，以便于大家查找。所以看到代码中类似于`// org.apache.shiro.SecurityUtils`的注释请大家不要疑惑。

# Shiro结构
![](https://shiro.apache.org/assets/images/ShiroBasicArchitecture.png)

## Subject
存储当前用户信息以及用户的权限、角色信息，并提供登录验证及。Subject同样可以保存第三方登录服务的信息，比如CAS的Token。下面介绍下Subject的一些常用方法。

**获取Subject**
```java
// org.apache.shiro.SecurityUtils
SecurityUtils.getSubject()
```
这个方法可以在程序的任何地方获取Subject，通过`getPrincipal()`方法可以获取到用户信息。通过`getSeesion()`方法可以获取到当前的Session。也就是说在程序的任何地方都可以获取到Session中存放的信息。

之所以可以在程序的任何地方获取到Subject是因为，Shiro使用`ThreadLocal`来存储Subject。对于Tomcat来说，每个请求过来都会从线程池中分配一个线程给这个请求使用。不只是Tomcat，大部分Web容器都是这么处理的。当请求到达Shiro时，shiro会获取当前的Subject，然后存放到`ThreadLocal`中。所以无论是在控制层还是业务层，都可以使用此方法获取Subject。


> 即便是在新建的线程中，或者Spring的异步方法中（因为异步方法是创建了新的线程）中仍然可以使用此方法获取Subject。因为Shiro用的是`InheritableThreadLocalMap`，可以实现父子线程数据的传递。

**Subject中的常用方法**
```java
// org.apache.shiro.subject.Subject
Subject subject = SecurityUtils.getSubject();
subject.isAuthenticated();  // 是否登录
subject.logout(); // 注销
subject.getSession(); // 获取当前Session（HTTPSession）
// 获取用户信息，可以是用户名、用户Bean。当前例子获取到的是用户名。后续章节将介绍如何改变它的值。
subject.getPrincipal(); 
subject.isPermitted(); // 用于判断是否有传入的权限
subject.isPermittedAll(); // 用于判断是否有传入的权限，可以传入多个权限
subject.checkPermissions(); // 权限验证，与isPermitted不同的是如果没有权限，则抛出AuthorizationException异常
subject.hasRole(); // 是否有角色
subject.hasRoles(); // 是否有角色，多个
subject.checkRole(); // 角色验证，与hasRole不同的是如果没有角色，则抛出AuthorizationException异常
subject.checkRoles(); // 角色验证，与hasRole不同的是如果没有角色，则抛出AuthorizationException异常
```
## SecurityManager
SecurityManager 是Shiro的心脏。连接Subject和Realm。负责Subject的创建、删除、维护等工作。SecurityManager一般只会有一个实例。
Subject中的对权限和角色的验证或校验的方法，在SecurityManager中也是有的，但是不推荐使用，因为Subject中的方法使用起来更加方便。

比如我们要验证一个角色
```java 
Subject subject = SecurityUtils.getSubject();

// 使用SubjectAPI
subject.checkRole("admin");

// 使用SecurityManager API，无法直接验证，依赖Subject
SecurityUtils.getSecurityManager().checkRole(subject.getPrincipals(), "admin");
```
这是Subject中`checkRole`的源码。
```java
public void checkRole(String role) throws AuthorizationException {
    assertAuthzCheckPossible(); // 验证principals是否存在，如果不存在跑出异常。
    securityManager.checkRole(getPrincipals(), role);
}
```
## Realms
用于获取用户信息和权限信息。作为连接Shiro和我们应用数据库的桥梁。一个系统中可以存在多个Realm。单Realm和多Realm的处理机制略有不同，详见`org.apache.shiro.authc.pam.ModularRealmAuthenticator`的`doSingleRealmAuthentication`和`doMultiRealmAuthentication`方法。

# Shiro Filter 初始化

`ShiroFilterFactoryBean`实现了`FactoryBean`。其实创建的是它的一个内部类`SpringShiroFilter`.
```java
// org.apache.shiro.spring.web.ShiroFilterFactoryBean

// 返回创建的Bean的实例
public Object getObject() throws Exception {
    if (instance == null) {
        instance = createInstance();
    }
    return instance;
}

// 创建的Bean的类型
public Class getObjectType() {
    return SpringShiroFilter.class;
}
```

从上面的代码可以看到Shiro是通过`createInstance()`实例来创建filter的。下面来分析下`createInstance()`中的代码。

```java
// org.apache.shiro.spring.web.ShiroFilterFactoryBean

protected AbstractShiroFilter createInstance() throws Exception {

    log.debug("Creating Shiro Filter instance.");

    SecurityManager securityManager = getSecurityManager();
    if (securityManager == null) {
        String msg = "SecurityManager property must be set.";
        throw new BeanInitializationException(msg);
    }

    if (!(securityManager instanceof WebSecurityManager)) {
        String msg = "The security manager does not implement the WebSecurityManager interface.";
        throw new BeanInitializationException(msg);
    }

    FilterChainManager manager = createFilterChainManager();
    
    PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();
    chainResolver.setFilterChainManager(manager);

    return new SpringShiroFilter((WebSecurityManager) securityManager, chainResolver);
}
```

**1. 初始化之前必须有`SecurityManager`实例，并且实现的是`WebSecurityManager`接口。**

**2. `FilterChainManager`实际上存储的是是一个路径到`filter`的映射信息。shiro默认会创建11个过滤器。**
```java
// enum org.apache.shiro.web.filter.mgt.DefaultFilter
anon(AnonymousFilter.class),
authc(FormAuthenticationFilter.class),
authcBasic(BasicHttpAuthenticationFilter.class),
logout(LogoutFilter.class),
noSessionCreation(NoSessionCreationFilter.class),
perms(PermissionsAuthorizationFilter.class),
port(PortFilter.class),
rest(HttpMethodPermissionFilter.class),
roles(RolesAuthorizationFilter.class),
ssl(SslFilter.class),
user(UserFilter.class);
```
也就是说这11个过滤器我们是可以直接使用的，但是它们用的都是默认的配置，所以在实际使用中我们需要用我们自己的配置来覆盖默认过滤器。

覆盖的方法很简单，我们只需要在配置`shiroFilter`时，将filter的名称设置的与上面一致，就可以覆盖默认的过滤器。比如我们的配置
```java
// <key=filterName，value=filter实例>
Map<String, Filter> filterMap = new LinkedHashMap<>();
filterMap.put("logout", logoutFilter);
filterMap.put("authc", authenticationFilter);
filterMap.put("roles", new RolesAuthorizationFilter());
shiroFilterFactoryBean.setFilters(filterMap);
```
在这里我们覆盖了`authc,logout,roles`三个过滤器。这里的roles过滤器是新建的实例，其实如果没有自定义内容这句配置是可以不要的。相信到这里大家已经知道我们为什么可以直接使用`anon`来配置权限了吧，因为这个过滤器是已经初始化过的，所以我们可以直接使用。Shiro创建过滤器的顺序就是上面的顺序，如果我们添加新的过滤器，则向后面追加。而覆盖的过滤器位置不变。

这里的`createFilterChainManager`方法中有一个地方需要注意，就是`applyGlobalPropertiesIfNecessary(filter);`这行代码。
```java
// org.apache.shiro.spring.web.ShiroFilterFactoryBean

private void applyGlobalPropertiesIfNecessary(Filter filter) {
    applyLoginUrlIfNecessary(filter); // AccessControlFilter
    applySuccessUrlIfNecessary(filter); // AuthenticationFilter
    applyUnauthorizedUrlIfNecessary(filter); //AuthorizationFilter
}

// 这里只列出来其中一个方法的代码，其他方法类似。
// 在这个方法中判断filter中的loginUrl是否为默认的地址，如果是默认的地址则设置成ShiroFilterFactoryBean中配置的地址。
private void applyLoginUrlIfNecessary(Filter filter) {
    String loginUrl = getLoginUrl();
    if (StringUtils.hasText(loginUrl) && (filter instanceof AccessControlFilter)) {
        AccessControlFilter acFilter = (AccessControlFilter) filter;
        //only apply the login url if they haven't explicitly configured one already:
        String existingLoginUrl = acFilter.getLoginUrl();
        if (AccessControlFilter.DEFAULT_LOGIN_URL.equals(existingLoginUrl)) {
            acFilter.setLoginUrl(loginUrl);
        }
    }
}
```
这段代码的意思就是会将`ShiroFilterFactoryBean`中配置的`loginUrl`应用到所有继承`AccessControlFilter`的过滤器中。`successUrl,unauthorizedUrl`应用到所有继承`AuthenticationFilter`的过滤器中。而从上面的代码中我们也可以看出，此处只会覆盖默认的配置，如果我们的filter中已经配置了`loginUrl`或`successUrl`这里是不会覆盖的。

**3. `PathMatchingFilterChainResolver`主要作用是根据request中的路径返回要执行的filter**
这里用的是`AntPathMatcher`路径匹配器。

**4. `SpringShiroFilter`是`ShiroFilterFactoryBean`的一个内部类，是shiro的核心过滤器。**
```java
// org.apache.shiro.spring.web.ShiroFilterFactoryBean

private static final class SpringShiroFilter extends AbstractShiroFilter {

    protected SpringShiroFilter(WebSecurityManager webSecurityManager, FilterChainResolver resolver) {
        super();
        if (webSecurityManager == null) {
            throw new IllegalArgumentException("WebSecurityManager property cannot be null.");
        }
        setSecurityManager(webSecurityManager);
        if (resolver != null) {
            setFilterChainResolver(resolver);
        }
    }
}
```

# Shiro登录处理流程
![](https://images.jaune162.com/images/shiro/4/2.png)

接受到请求之后首先执行的是`AbstractShiroFilter`中的`doFilterInternal()`方法。
```java
// org.apache.shiro.web.servlet.AbstractShiroFilter#doFilterInternal
protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse, final FilterChain chain)
        throws ServletException, IOException {

    Throwable t = null;

    try {
        final ServletRequest request = prepareServletRequest(servletRequest, servletResponse, chain);
        final ServletResponse response = prepareServletResponse(request, servletResponse, chain);

        final Subject subject = createSubject(request, response);

        //noinspection unchecked
        subject.execute(new Callable() {
            public Object call() throws Exception {
                updateSessionLastAccessTime(request, response);
                executeChain(request, response, chain);
                return null;
            }
        });
    } catch (ExecutionException ex) {
        t = ex.getCause();
    } catch (Throwable throwable) {
        t = throwable;
    }

	// ...
}
```
`doFilterInternal`这个方法是所有请求的入口。Shiro之所以在程序的任何位置都能获取到`Subject`就是因为这里的`subject.execute`，这个方法其实执行的是`SubjectCallable.call()`。
```java
public V call() throws Exception {
    try {
        threadState.bind();
        return doCall(this.callable);
    } finally {
        threadState.restore();
    }
}
```
然后在这里通过`SubjectThreadState.bind`将Subject绑定到了`ThreadLocal`中。

然后在回调中执行了`executeChain`方法，限于篇幅，此处只粘贴核心代码。
```java
protected FilterChain getExecutionChain(ServletRequest request, ServletResponse response, FilterChain origChain) {
    FilterChain chain = origChain;

    FilterChainResolver resolver = getFilterChainResolver();
    if (resolver == null) {
        log.debug("No FilterChainResolver configured.  Returning original FilterChain.");
        return origChain;
    }

    FilterChain resolved = resolver.getChain(request, response, origChain);
    if (resolved != null) {
        log.trace("Resolved a configured FilterChain for the current request.");
        chain = resolved;
    } else {
        log.trace("No FilterChain configured for the current request.  Using the default.");
    }

    return chain;
}


protected void executeChain(ServletRequest request, ServletResponse response, FilterChain origChain)
        throws IOException, ServletException {
    FilterChain chain = getExecutionChain(request, response, origChain);
    chain.doFilter(request, response);
}
```
从`FilterChainResolver `中获取`FilterChain`然后执行。因为我们访问的是`/login`，所以匹配到的filter是`FormAuthenticationFilter`。那么`FormAuthenticationFilter`是如何处理请求的呢？我们接着忘下扒。

从父类`AccessControlFilter`的`onPreHandle`方法中，可以看到先执行了`isAccessAllowed`方法，如果`isAccessAllowed`方法返回的值是`false`，那么就执行`onAccessDenied`方法。
```java
// org.apache.shiro.web.filter.AccessControlFilter#onPreHandle
public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
	// 如果isAccessAllowed的返回值为true，则不会执行后面的代码。
    return isAccessAllowed(request, response, mappedValue) || onAccessDenied(request, response, mappedValue);
}

// 上面的逻辑等同于下面的代码。
public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
    if (!isAccessAllowed(request, response, mappedValue)) {
		return onAccessDenied(request, response, mappedValue);
	} else {
		return true;
	}
}
```
我们再看`isAccessAllowed`方法。

```java
// org.apache.shiro.web.filter.authc.AuthenticatingFilter#isAccessAllowed
@Override
protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
    return super.isAccessAllowed(request, response, mappedValue) ||
            (!isLoginRequest(request, response) && isPermissive(mappedValue));
}

// super.isAccessAllowed()
// org.apache.shiro.web.filter.authc.AuthenticationFilter#isAccessAllowed
protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
    Subject subject = getSubject(request, response);
    return subject.isAuthenticated();
}
```
从上面的代码中可以看到允许访问的条件是，用户已登录或者不是登录请求并且是**宽容模式**。这里对宽容模式做一个简单的介绍。宽容模式与`anon`类似，配置方法为`filterChainDefinitionMap.put("/permissive", "authc[permissive]");`意思就是虽然需要登录才能访问，但是不登录也可以访问。

从这里我们就可以看出，如果我们没有登录并且所请求的资源不是**宽容模式**则是会直接跳转到，`onAccessDenied`方法的。

```
protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
    if (isLoginRequest(request, response)) { // 判断是否为登录地址
        if (isLoginSubmission(request, response)) { // 是否为POST请求，如果是POST请求则认为是提交的登录表单。
            if (log.isTraceEnabled()) {
                log.trace("Login submission detected.  Attempting to execute login.");
            }
            return executeLogin(request, response); // 执行登录流程
        } else { // 如果是不是POST请求，则允许继续向下执行，也就是允许访问登录页面。
            if (log.isTraceEnabled()) {
                log.trace("Login page view.");
            }
            //allow them to see the login page ;)
            return true;
        }
    } else {
        if (log.isTraceEnabled()) {
            log.trace("Attempting to access a path which requires authentication.  Forwarding to the " +
                    "Authentication url [" + getLoginUrl() + "]");
        }
		// 保存请求的地址，并且跳转到登录页面。这里保存的请求地址，在登录成功之后会回调到这个地址。如果没有或者直接访问的登录页面，则会跳转到配置的成功页面。
        saveRequestAndRedirectToLogin(request, response);
        return false;
    }
}
```

到此登录处理的主流程基本已理清楚了，下一章我们讲`executeLogin`方法做了什么。这才是登录的核心业务，理解了这一部分也就掌握了如何将Shiro和数据库结合起来。

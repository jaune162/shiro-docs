# 让shiro环境跑起来--shiro配置

---

# 配置

## application.yml
SpringBoot 支持`yml`和`properties`两种配置格式。
```yaml
server:
  port: 8081 # Tomcat服务端口，SpringBoot中默认使用的是Tomcat
spring:
  freemarker:
    suffix: .html # 默认的是.ftl
  mvc:
    static-path-pattern: /static/** # 设置静态资源访问路径
  resources:
    static-locations: classpath:/static # 设置静态资源文件夹
```
## MainController
这是一个测试用的控制器，用于测试权限的配置是否生效
```java
/*
 * Copyright © 2018 CODESTD.COM Inc. All rights reserved.
 */
package com.codestd.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

/**
 * 主控制器
 *
 * @author jaune
 * @since 1.0.0
 */
@Controller
public class MainController {

    @GetMapping("/")
    public ModelAndView home() {
        return new ModelAndView("index");
    }

    @ResponseBody
    @GetMapping("/anonymous")
    public String main() {
        return "任何人都可以访问我";
    }

    @ResponseBody
    @GetMapping("/authc")
    public String authc() {
        return "需要登录才能访问";
    }

    @ResponseBody
    @GetMapping("/role")
    public String role() {
        return "需要有Admin角色才能访问";
    }
}

```
## shiro配置

### SessionListener
创建`ShiroSessionListener`实现`org.apache.shiro.session.SessionListener`接口。用于监听Session创建、关闭等事件。
```java
/**
 * session 监听，用于处理Session创建、关闭、过期等事件。
 * @author jaune
 * @since 1.0.0
 */
public class ShiroSessionListener implements SessionListener {

    @Override
    public void onStart(Session session) {

    }

    @Override
    public void onStop(Session session) {

    }

    @Override
    public void onExpiration(Session session) {

    }
}

```
如果没有相关业务，可以没有这个类。

### shiro配置
创建类`ShiroConfiguration`
```java
/*
 * Copyright © 2018 CODESTD.COM Inc. All rights reserved.
 */
package com.codestd.security.config;

import com.codestd.security.shiro.listener.ShiroSessionListener;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shiro 配置
 *
 * @author jaune
 * @since 1.0.0
 */
@Configuration
public class ShiroConfiguration {

    @Bean
    public SessionListener sessionListener() {
        return new ShiroSessionListener();
    }

    @Bean
    public DefaultWebSessionManager sessionManager(
            @Qualifier("sessionListener") SessionListener sessionListener) {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.getSessionListeners().add(sessionListener);
        return sessionManager;
    }

    /**
     * 凭证管理，用于根据Token获取用户信息及用户权限角色信息
     */
    @Bean
    public Realm realm() {
        SimpleAccountRealm accountRealm = new SimpleAccountRealm();
        accountRealm.addAccount("user1", "123456");
        accountRealm.addAccount("admin", "123456", "admin");
        return accountRealm;
    }

    /**
     * 处理用户登录、注销、权限认证等核心业务，是Shiro的心脏
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

    /**
     * 登录过滤器，用于拦截登录请求并处理登录请求
     */
    @Bean
    public FormAuthenticationFilter authenticationFilter() {
        return new FormAuthenticationFilter();
    }

    /**
     * 设置不向Web容器中注册登录过滤器
     */
    @Bean
    public FilterRegistrationBean unregistrationFormAuthenticationFilter(
            @Qualifier("authenticationFilter") FormAuthenticationFilter authenticationFilter) {
        FilterRegistrationBean<FormAuthenticationFilter> registration =
                new FilterRegistrationBean<>(authenticationFilter);
        registration.setEnabled(false);
        return registration;
    }

    /**
     * 注销过滤器
     */
    @Bean
    public LogoutFilter logoutFilter() {
        LogoutFilter logoutFilter = new LogoutFilter();
        logoutFilter.setRedirectUrl("/");
        return logoutFilter;
    }

    /**
     * 不向Web容器中注册注销过滤器
     */
    @Bean
    public FilterRegistrationBean<LogoutFilter> unregistrationLogoutFilter(
            @Qualifier("logoutFilter") LogoutFilter logoutFilter) {
        FilterRegistrationBean<LogoutFilter> registration =
                new FilterRegistrationBean<>(logoutFilter);
        registration.setEnabled(false);
        return registration;
    }

    /**
     * 核心过滤器
     */
    @Bean("shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(
            @Qualifier("securityManager") DefaultWebSecurityManager securityManager,
            @Qualifier("logoutFilter") LogoutFilter logoutFilter,
            @Qualifier("authenticationFilter") FormAuthenticationFilter authenticationFilter) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        // 设置登录页面的地址和登录请求提交的地址，一个是GET一个是POST。
        shiroFilterFactoryBean.setLoginUrl("/login"); 
        // 设置登录成功之后的默认的跳转页面。
        shiroFilterFactoryBean.setSuccessUrl("/");

        Map<String, Filter> filterMap = new LinkedHashMap<>();
        filterMap.put("logout", logoutFilter);
        filterMap.put("authc", authenticationFilter);
        shiroFilterFactoryBean.setFilters(filterMap);
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        filterChainDefinitionMap.put("/favicon.ico", "anon");
        filterChainDefinitionMap.put("/static/**", "anon");
        filterChainDefinitionMap.put("/anonymous", "anon");
        filterChainDefinitionMap.put("/logout", "logout");
        filterChainDefinitionMap.put("/authc", "authc");
        filterChainDefinitionMap.put("/role", "roles[admin]");
        filterChainDefinitionMap.put("/**", "authc");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }
}

```
>`accountRealm.addAccount("admin", "123456", "admin")`
>注意这行代码，第三个参数是一个可变参数，用于设置用户角色。API为`addAccount(String username, String password, String... roles)`

----
> `logoutFilter.setRedirectUrl`配置注销成功之后跳转的地址。

----

>`ShiroFilterFactoryBean`中还有一个`setUnauthorizedUrl()`方法，这个是配置权限认真失败后跳转的页面，如果没有配置在SpringBoot项目中将跳到SpringBoot的错误页面，并打印401错误信息，在常规的Web项目中将进入Tomcat的401异常页面。

----
 
> 此处的`filterChainDefinitionMap.put("/role", "roles[admin]");`配置表示需要有`admin`角色才能访问此资源，使用的是`RolesAuthorizationFilter`角色过滤器，这个过滤器是Shiro在启动时，自动配置的。在后面的章节中会有详细的介绍。这里我们使用的shiro提供的角色过滤器。后续章节会讲shiro的其他过滤器及使用方法，以及如何扩展它们。

地址的匹配默认使用的是`org.apache.shiro.util.AntPathMatcher`，规则如下：
- `?` 匹配一个字符
- `*` 匹配0个或多个字符
- `**` 匹配 0个或多个目录，会匹配下级所有目录

使用举例

- `/te*t`会匹配到`/test`、`/teat`、`/tebt`但是不会匹配到`/teaat`
- `/test/*`会匹配到`/test/`、`/test/a`、`/test/abc`但是不会匹配到、`/test/abc/def`
- `/test/**`会匹配到`/test/`、`/test/abc`、`/test/abc/def`及其下的所有子目录


----

> 注意这里的`FilterRegistrationBean`，这里配置的是`setEnabled(false)`。这是禁用过滤器的意思，就是不会将过滤器注册到Web容器中。之所以这样设置是因为SpringBoot会自动将实现`javax.servlet.Filter`的Bean注册到Web容器中。如果不设置禁用过滤器，则这个过滤器就会与`shiroFilter`中的过滤器链冲突，出现一些莫名其妙的错误。

### 登录控制器

```java
/*
 * Copyright © 2018 CODESTD.COM Inc. All rights reserved.
 */
package com.codestd.security.controller;

import org.apache.shiro.SecurityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

/**
 * 登录控制器
 *
 * @author jaune
 * @since 1.0.0
 */
@Controller
public class LoginController {

    /**
     * 跳转到登录页面
     */
    @GetMapping("/login")
    public ModelAndView toLoginPage() {
        return new ModelAndView("login");
    }

    /**
     * 注销
     */
    @GetMapping("/logout")
    public void logout() {
	    // 这里的isAuthenticated方法用户验证用户是否登录
        if (SecurityUtils.getSubject().isAuthenticated()) {
            SecurityUtils.getSubject().logout();
        }
    }

}
```

index.html和login.html的内容在此不再赘述，从这里(<https://gitee.com/jaune/spring-boot-shiro/tree/V1.0.0/>)可以查看项目的源码

# 测试

**GET:** `/anonymous`

![Alt text](https://images.jaune162.com/images/shiro/3/1.png)


**GET:**`/`

![Alt text](https://images.jaune162.com/images/shiro/3/2.png)

跳转到了登录页面

输入`admin/123456`跳转到首页

![Alt text](https://images.jaune162.com/images/shiro/3/3.png)

**GET:** `/authc`

![Alt text](https://images.jaune162.com/images/shiro/3/4.png)

**GET:** `/role`

![Alt text](https://images.jaune162.com/images/shiro/3/5.png)

**GET:** `/logout`
跳回到登录页面，这时我们切换成`user1/123456`

**GET:** `/authc`

![Alt text](https://images.jaune162.com/images/shiro/3/6.png)

**GET:** `/role`

![Alt text](https://images.jaune162.com/images/shiro/3/7.png)

这时报了401权限不足的异常，证明我们的配置已经生效。

> **注意**
> 网上的一些配置中是将`loginUrl`和`successUrl`配置到`FormAuthenticationFilter`中的，这种方式是不推荐的。因为这种方式的配置是存在问题的。正确的配置方式是配置到`ShiroFilterFactoryBean`中。因为只有配置到`ShiroFilterFactoryBean`中，Shiro才能在初始化过滤器的时候，为所有过滤器添加这项配置。后面的章节会有详细的讲述。

# 登录处理
## 已登录直接跳转到首页
通常我们会对登录页面做这样的处理：如果用户已登录，访问登录页面时直接跳转到首页。一是为了用户体验友好，二是避免后端出现过多的重复Session。其实这样做的目的就是为了限制用户不重复登录。

修改`LoginController#toLoginPage()`方法如下。
```java
/**
 * 跳转到登录页面，如果用户已登录则自动跳转到首页
 */
@GetMapping("/login")
public ModelAndView toLoginPage() {
    if (SecurityUtils.getSubject().isAuthenticated()) {
        return new ModelAndView("index");
    } else {
        return new ModelAndView("login");
    }
}
```
这样虽然跳到了首页，但是地址还是`http://localhost:8081/login`，所以`return new ModelAndView("index");`要改为`return new ModelAndView("redirect:/");`。

这样仍然不完美，因为我们在shiro中配置了，登录成功请求的地址，如果在此处写死的话，登录地址变更则需要改两处。有两种解决方案：

一种是注入`FormAuthenticationFilter`从`FormAuthenticationFilter`中获取成功后的跳转路径。
```java
@Autowired
private FormAuthenticationFilter authenticationFilter;

/**
 * 跳转到登录页面，如果用户已登录则自动跳转到首页
 */
@GetMapping("/login")
public ModelAndView toLoginPage() {
    if (SecurityUtils.getSubject().isAuthenticated()) {
        return new ModelAndView("redirect:" + this.authenticationFilter.getSuccessUrl());
    } else {
        return new ModelAndView("login");
    }
}
```
>源码：<https://gitee.com/jaune/spring-boot-shiro/tree/V1.0.1/>

一种是使用配置文件

首先增加配置Bean
```java
/*
 * Copyright © 2018 CODESTD.COM Inc. All rights reserved.
 */
package com.codestd.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 系统配置
 *
 * @author jaune
 * @since 1.0.0
 */
@Data  // 使用此注解可以自动生成getter和setter
@ConfigurationProperties(prefix = "system")
public class SystemSettings {
    private String loginSuccessUrl;
}
```

在`SpringBootShiroApplication`上增加注解`@EnableConfigurationProperties({SystemSettings.class})`。

然后在`application.yml`中增加
```yaml
system:
  login-success-url: /
```

以上部分可以参考官方文档的相关说明，<https://docs.spring.io/spring-boot/docs/2.0.3.RELEASE/reference/htmlsingle/#boot-features-external-config-typesafe-configuration-properties>

修改`ShiroConfiguration`中`FormAuthenticationFilter`的配置为
```
@Autowired
private SystemSettings systemSettings;

@Bean("shiroFilter")
public ShiroFilterFactoryBean shiroFilter(
        @Qualifier("securityManager") DefaultWebSecurityManager securityManager,
        @Qualifier("logoutFilter") LogoutFilter logoutFilter,
        @Qualifier("authenticationFilter") FormAuthenticationFilter authenticationFilter) {
    ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
    shiroFilterFactoryBean.setSecurityManager(securityManager);
    shiroFilterFactoryBean.setLoginUrl("/login");
    shiroFilterFactoryBean.setSuccessUrl(this.systemSettings.getLoginSuccessUrl());

	//...
}
```

修改`LoginController`为

```java
@Autowired
private SystemSettings systemSettings;

/**
 * 跳转到登录页面，如果用户已登录则自动跳转到首页
 */
@GetMapping("/login")
public ModelAndView toLoginPage() {
    if (SecurityUtils.getSubject().isAuthenticated()) {
        return new ModelAndView("redirect:" + this.systemSettings.getLoginSuccessUrl());
    } else {
        return new ModelAndView("login");
    }
}
```

>源码：<https://gitee.com/jaune/spring-boot-shiro/tree/V1.0.2/>

## 获取登录错误信息

在`LoginController`中增加
```java
// 在登录失败之后过滤器会放行，走到这里。并且会在request中携带错误信息。
@PostMapping("/login")
public void login(HttpServletRequest request, Model model) {
    String errorClassName = (String)request.getAttribute(
            FormAuthenticationFilter.DEFAULT_ERROR_KEY_ATTRIBUTE_NAME);
    final String ERROR_MESSAGE_ATTR_NAME = "errorMessage";

    if (errorClassName != null) {
        errorClassName = errorClassName.substring(errorClassName.lastIndexOf(".") + 1);
    } else {
        return;
    }
    switch (errorClassName) {
        case "IncorrectCredentialsException":
            model.addAttribute(ERROR_MESSAGE_ATTR_NAME, "密码错误！");
            break;
        case "UnknownAccountException":
            model.addAttribute(ERROR_MESSAGE_ATTR_NAME, "用户名不存在！");
            break;
        case "DisabledAccountException":
            model.addAttribute(ERROR_MESSAGE_ATTR_NAME, "账户已被禁用！");
            break;
        case "LockedAccountException":
            model.addAttribute(ERROR_MESSAGE_ATTR_NAME, "账户已被锁定！");
            break;
        default:
            model.addAttribute(ERROR_MESSAGE_ATTR_NAME, "登录失败！");
    }
}
```
在前台可以使用`${errorMessage}`获取错误信息。`<div class="error">${errorMessage}</div>`

>源码：<https://gitee.com/jaune/spring-boot-shiro/tree/V1.0.3/>

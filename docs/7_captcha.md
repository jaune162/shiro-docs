# 增加验证码功能

---

# 验证码生成
本教程中使用的是`kaptcha`。
```xml
<dependency>
    <groupId>com.github.penggle</groupId>
    <artifactId>kaptcha</artifactId>
    <version>2.3.2</version>
</dependency>
```

由于`kaptcha`提供的是一个`Servlet`。所以我们直接以Servlet的方式使用。如下
```java
@WebServlet(urlPatterns = "/captcha")
public class CaptchaController extends KaptchaServlet {

}
```
需要在`SpringBootShiroApplication`上添加`@ServletComponentScan`注解启用SpringBoot的`Servlet`扫描功能。

然后在页面中增加验证码输入的文本框，name属性为`captcha`。

# 自定义Token
自定义一个Token`CaptchaUsernamePasswordToken`继承自`UsernamePasswordToken`。
```java
public class CaptchaUsernamePasswordToken extends UsernamePasswordToken {

    private String captcha;

    public CaptchaUsernamePasswordToken(){
    }

    public CaptchaUsernamePasswordToken(String username, String password, boolean rememberMe, String host, String captcha) {
        super(username, password, rememberMe, host);
        this.captcha = captcha;
    }

    public String getCaptcha() {
        return captcha;
    }

    public void setCaptcha(String captcha) {
        this.captcha = captcha;
    }
}
```

# 自定义AuthenticationFilter
自定义一个`AuthenticationFilter`重写`createToken`方法，返回`CaptchaUsernamePasswordToken`。

```java
public class CaptchaFormAuthenticationFilter extends FormAuthenticationFilter {

    private static final String  DEFAULT_CAPTCHA_PARAM = "captcha";

    private String captchaParamName;

    public String getCaptchaParamName() {
        return this.captchaParamName != null ? this.captchaParamName : DEFAULT_CAPTCHA_PARAM;
    }

    public void setCaptchaParamName(String captchaParamName) {
        this.captchaParamName = captchaParamName;
    }

    protected AuthenticationToken createToken(String username, String password,
                                              ServletRequest request, ServletResponse response) {
        boolean rememberMe = isRememberMe(request);
        String host = this.getHost(request);
        String captcha = this.getCaptcha(request);
        return new CaptchaUsernamePasswordToken(username, password, rememberMe, host, captcha);
    }

    private String getCaptcha(ServletRequest request) {
        return WebUtils.getCleanParam(request, this.getCaptchaParamName());
    }

}
```
在这里只处理Token就可以了，其他的事情不用做。如果不理解的话，请再回过头看看源码分析的两章。

# 在DatabaseRealm中增加验证码校验
首先创建一个`CaptchaException`继承自`org.apache.shiro.authc.AuthenticationException`。在验证码发生错误的时候我们要抛出这个异常，然后再`LoginController`处理这个异常。

```java
public class CaptchaException extends AuthenticationException {

    public CaptchaException() {
        super();
    }

    public CaptchaException(String message) {
        super(message);
    }
}
```
增加校验验证码的逻辑
```java
// 首先增加验证码校验逻辑
/**
 * 如果验证码为空或验证码错误，则抛出CaptchaException
 */
private void checkCaptcha(AuthenticationToken token) {
    CaptchaUsernamePasswordToken usernamePasswordToken = (CaptchaUsernamePasswordToken) token;
    String captcha = usernamePasswordToken.getCaptcha();
    if (captcha == null) {
        throw new CaptchaException();
    }
    Session session = SecurityUtils.getSubject().getSession();
    // Kaptcha生成的验证码是放在session中的。
    // session key就是com.google.code.kaptcha.Constants.KAPTCHA_SESSION_KEY
    String sessionCaptcha = (String) session.getAttribute(Constants.KAPTCHA_SESSION_KEY);
    if (!captcha.equals(sessionCaptcha)) {
        throw new CaptchaException();
    }
}
```

修改`doGetAuthenticationInfo`增加验证码校验的流程。
```java
@Override
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

    this.checkCaptcha(token); // 在此处校验验证码

    SysUser user = this.sysUserMapper.findByUsernameOrPhoneNumber(usernamePasswordToken.getUsername());

    // ...下面的省略
}
```

# 处理验证码错误返回的错误信息
修改`loginController`为
```java
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
        case "CaptchaException": // 处理验证码错误
            model.addAttribute(ERROR_MESSAGE_ATTR_NAME, "验证码输入错误！");
            break;
        default:
            model.addAttribute(ERROR_MESSAGE_ATTR_NAME, "登录失败！");
    }
}
```
只要是在`doGetAuthenticationInfo`中抛出的`AuthenticationException`都能在这里获取到。

# 修改配置
```java
@Bean
public FormAuthenticationFilter authenticationFilter() {
    return new FormAuthenticationFilter();
}
// 改为
@Bean
public CaptchaFormAuthenticationFilter authenticationFilter() {
    return new CaptchaFormAuthenticationFilter();
}
```

因为`CaptchaFormAuthenticationFilter`是继承自`FormAuthenticationFilter`的，所以`ShiroFilterFactoryBean`注入的配置不用修改。

```java
// 就是这一句
@Qualifier("authenticationFilter") FormAuthenticationFilter authenticationFilter
```

然后将`/captcha`设置为不需任何权限即可访问。
```java
filterChainDefinitionMap.put("/captcha", "anon");
```

>可以从 <https://gitee.com/jaune/spring-boot-shiro/tree/V2.0.0> 获取上面实例的代码。

# 密码错误3次后再输入验证码
我们先来分析要实现这个功能，都需要做哪些事情。总结为下面三点。
1. 如何记录登录错误次数？
2. 如何告诉前端页面是否显示验证码输入框？
3. 如何告诉Realm是否需要校验验证码？

想一想是不是只要记录了错误次数，那么其他的两个问题是不是就很好解决了呢？

先来思考**第一个问题：** *如何记录登录错误次数？*
回顾一下之前讲的登录过滤器是`FormAuthenticationFilter`，那么应该首先想到的就是它了。然后找找看有没有和登录相关的方法。是不是有个`onLoginFailure`方法，没错！这个是处理登录失败的逻辑。我们可以在这里写记录登录错误次数的逻辑。

那么另外一个问题：错误次数如何保存？这时我们应该首先想到的就是`session`。为了防止注销后再登录时仍然需要输入验证码，我们需要在`onLoginSuccess`*（登录成功的处理方法）*中清除错误次数记录。

Let's go!，先来实现这一部分的功能。

```java
private int maxErrorTimes = 3; // 这里为了扩展方便，将错误次数设置成可配置参数

// ... maxErrorTimes getter and setter

@Override
protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
	// 密码错误抛出IncorrectCredentialsException异常，只有在密码输入错误时才累加错误次数。
	if (e instanceof IncorrectCredentialsException) {
		Integer errorTimes = this.incrementErrorTimes((HttpServletRequest) request);
	}
    return super.onLoginFailure(token, e, request, response);
}

@Override
protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
    this.clearErrorTimes(subject);
    return super.onLoginSuccess(token, subject, request, response);
}

/**
 * 累加错误次数
 */
private Integer incrementErrorTimes(HttpServletRequest request) {
    HttpSession session = request.getSession();
    Integer errorTimes = (Integer) session.getAttribute(ERROR_TIMES_KEY);
    if (errorTimes == null) {
        errorTimes = 1;
    } else {
        errorTimes++;
    }
    session.setAttribute(ERROR_TIMES_KEY, errorTimes);
    return errorTimes;
}

/**
 * 清除错误次数
 */
private void clearErrorTimes(Subject subject) {
    Session session = subject.getSession();
    session.removeAttribute(ERROR_TIMES_KEY);
}
```

接着思考第二个问题和第三个问题。既然我们已经记录了错误次数，那么我们只需要在进入页面之前给页面一个参数告诉页面需要验证码，页面根据参数判断是否显示验证码。然后在验证Token之前，告诉`Realm`本次验证需要校验验证码。

观察`onLoginFailure`方法有个参数是`request`，那么我们就可以在这里判断错误次数，如果大于或等于3次就向页面传递一个参数告诉页面需要显示验证码输入框。
再看`createToken`方法，我们也可以在创建`Token`时，直接向Token中设置是否需要校验验证码，只需要在Token中增加一个参数即可。

让我们接着完成剩下的代码。

先处理页面显示/隐藏验证码输入框的问题
```java
@Override
protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
    // 密码错误抛出IncorrectCredentialsException异常，只有在密码输入错误时才累加错误次数。
    Integer errorTimes = null;
    if (e instanceof IncorrectCredentialsException) {
        errorTimes = this.incrementErrorTimes((HttpServletRequest) request);
    }
    // 如果是其他错误，需要重新获取错误次数
    if (errorTimes == null) {
        errorTimes = getErrorTimes((HttpServletRequest) request);
    }
    // 判断错误次数，如果错误次数超过maxErrorTimes，那么向页面转传递一个needCaptcha的参数
    if (errorTimes >= this.maxErrorTimes) {
        request.setAttribute("needCaptcha", true);
    }

    return super.onLoginFailure(token, e, request, response);
}

/**
 * 获取登录错误的次数
 */
private Integer getErrorTimes(HttpServletRequest request) {
    HttpSession session = request.getSession();
    Integer errorTimes = (Integer) session.getAttribute(ERROR_TIMES_KEY);
    if (errorTimes == null) {
        errorTimes = 0;
    }
    return errorTimes;
}
```
然后在页面上增加对`needCaptcha`的判断
```xml
<!--主要看这里-->
<#if needCaptcha?? && needCaptcha>
	<div class="row">
	    <div class="col-lg-3" style="padding-right: 0px;">验证码：</div>
	    <div class="col-lg-4" style="padding-left: 0px;">
	        <input type="text" name="captcha"
	               class="form-control" aria-label="...">
	    </div>
	    <div class="col-lg-4" style="padding-left: 0px;">
	        <img id="captcha" src="/captcha" height="35" width="125" onclick="refreshCaptcha()">
	    </div>
	</div>
</#if>
```

然后处理`Realm`是否需要校验验证码的问题。

在`CaptchaUsernamePasswordToken`中增加属性`needCheckCaptcha`，用于让`Realm`根据这个参数判断是否需要校验验证码。
```java
private boolean needCheckCaptcha = false;
// getter and setter
```

修改`createToken`方法
```java
protected AuthenticationToken createToken(String username, String password,
                                          ServletRequest request, ServletResponse response) {
    boolean rememberMe = isRememberMe(request);
    String host = this.getHost(request);
    String captcha = this.getCaptcha(request);
    CaptchaUsernamePasswordToken token = 
            new CaptchaUsernamePasswordToken(username, password, rememberMe, host, captcha);
    if (this.needCheckCaptcha((HttpServletRequest) request)) {
        token.setNeedCheckCaptcha(true);
    }
    return token;
}
/**
 * 判断是否需要校验验证码
 */
private boolean needCheckCaptcha(HttpServletRequest request) {
    return this.getErrorTimes(request) >= this.maxErrorTimes;
}
```
然后修改`DatabaseRealm`中的`checkCaptcha`方法。
```java
/**
 * 如果验证码为空或验证码错误，则抛出CaptchaException
 */
private void checkCaptcha(AuthenticationToken token) {
    CaptchaUsernamePasswordToken usernamePasswordToken = (CaptchaUsernamePasswordToken) token;
    // 判断是否需要校验验证码
    if (!usernamePasswordToken.isNeedCheckCaptcha()) {
        return;
    }
    String captcha = usernamePasswordToken.getCaptcha();
    if (captcha == null) {
        throw new CaptchaException();
    }
    Session session = SecurityUtils.getSubject().getSession();
    String sessionCaptcha = (String) session.getAttribute(Constants.KAPTCHA_SESSION_KEY);
    if (!captcha.equals(sessionCaptcha)) {
        throw new CaptchaException();
    }
}
```

修改完之后重启即可看到效果了。因为此功能是基于Session的，所以如果关闭浏览器之后再重新打开，那么因为session失效了，所以打开的登录页面是没有验证码的。如果要实现重新打开之后仍然需要验证码，则需要借助Cookie（可以在浏览器端被修改也不安全）或记录客户端IP到缓存实现，实现起来会比较复杂。验证码的目的是为了阻止暴力破解和一些批量脚本，只要目的达到即可。本例源码 <https://gitee.com/jaune/spring-boot-shiro/tree/V2.0.1>

> **思考**
>
> 1. 如何实现在用户的密码错误5次之后，禁止在当前浏览器登陆。
> 2. 在某一个用户的密码连续输入错误n次之后，将用户冻结。

# 无状态服务实现原理

---

无状态服务简单的理解就是没有Session，如果没有Session那么shiro就无法将用户信息保存在Session中，从Subject中也将获取不到Session。那么我们要怎么处理呢？

首先需要确定的是需要将登录后的用户信息保存起来。这里我们使用JWT对用户数据进行加密，生成一个Token，然后在登录的成功时候传到前端。前端保存这个Token，然后每次访问数据的时候，在请求头中加上这个Token，而这个Token中就是用户信息的密文，后端可以通过解析Token获取用户信息。然后在后端通过判断Token是否有效，来决定用户是否需要登录。

# 禁用Session
既然用使用无状态服务，那么就肯定不能再使用Session了，所以在这里要先禁止Shiro使用Session。同时要注意这个异常信息：
>Session creation has been disabled for the current subject.  This exception indicates that there is either a programming error (using a session when it should never be used) or that Shiro's configuration needs to be adjusted to allow Sessions to be created for the current Subject.  See the org.apache.shiro.subject.support.DisabledSessionException JavaDoc for more.

这个异常通常是调用了`subject.getSession`方法，这里还要注意，**过滤器中使用session的方法需要重写**。比如`saveRequest`方法，这个方法是在访问有权限的资源并且用户没有登录时，保存访问的资源到session中，然后登录成功之后再从session中获取到访问的资源地址，然后跳转到资源地址。但是在无状态服务中这通常是不需要的，没有权限直接返回没有权限的信息即可，前端会根据错误信息做相应的处理。

# 创建Token

这里使用JWT创建token，JWT创建的Token是一串加密字符串。如下：
```
eyJraWQiOiIxIiwidHlwIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhZG1pbiIsImlzcyI6IkNPREVTVEQiLCJpYXQiOjE1MzI5OTU1NTEsImp0aSI6IjU0MzgxMjhiYmRkNTQ4NWZhMGNmZDBlYWFiMTc2Mjk3In0.UDWQVsOutNS_GsWrJ1JCf_avtT_IGZvp7H-Z4guBEMA
```
这个字符串里可以存用户ID、用户名、Token创建时间、Token过期时间等信息。存的信息越多，字符串的长度越长。因为这个字符串是要放在请求头中的，而且每次访问都要带，所以在这里建议不要存太多信息，只存必要信息即可。

> 这个相当于`accessToken`。或者说它就是`accessToken`。

# Token使用及管理

这里提供两种方式，并介绍两种方式如何共存。但是有一个原则就是无论哪种方式，用户信息都是放在Token中的，这个Token前端或移动端无法解析，只能后端解析。对于前端来说Token就相当于一张门禁卡，能开门，但是你不知道门禁卡中存储的信息。

## 模拟Session
既然是模拟Session那么就要在后端维护Token的生命周期。虽然JWT生成的Token中有过期时间，但是这个有效期不可更改，因为更改后Token就变了，所以我们不再使用Token中的过期时间。而是使用通过缓存，自己维护的过期时间。

### 登录并生成Token的流程
![](https://images.jaune162.com/images/shiro/14/1.png)

### 访问资源并创建Subject的流程
![](https://images.jaune162.com/images/shiro/14/2.png)

>**要点**
>1. 创建Token
>2. 创建Subject
>3. 刷新Token


## 使用RefreshToke获取AccessToken
上面的处理方式比较适合PC端Web项目，对于移动端项目就不太适用了，因为移动端通常是免登陆的。登录一次可以很长时间不用再次登录。
这就需要用现在比较流行的`refreshToken accessToken`模式了。这种方案相对比较成熟。现在的应用范围也比较广。

> 这里简单说下`refreshToken accessToken`。大家所熟知的OATH2采用的就是这种方式。`refreshToken`是一个有效期较长的Token，而`accessToken`的有效期很短，通常之后半小时或更短。也就是说经常在网络中传输的是`accessToken`，所以`accessToken`有很大的可能发生泄漏，而为`accessToken`设置较短的有效时间可以减少泄漏带来的损失。因为`assessToken`有效期很短，那总不能一直让用户登录吧，所以`refreshToken`就派上用场了。`refreshToken`就是用来更新`accessToken`的，通常`refreshToken`使用一次之后就失效了，更新`accessToken`时会返回新的`refreshToken`。

为了提升安全性，在本实例中我们限制同一种设备（Android、IOS），同一个用户只能登录一次。因为refreshToken是保存在缓存中的，所以我们可以将用户和refreshToken建立联系，在用户登录成功后将原来的refreshToken从缓存中删除。

这种方式与第一种方式的主要区别就在于登录和生成Token，因为这种方式可以使用`refreshToken`，而创建Token时要同时生成`refreshToken`和`accessToken`。

### 登录流程
![](https://images.jaune162.com/images/shiro/14/3.png)

# 创建Subject
大家知道Subject是shiro的核心，但是Subject的创建是依赖于Session的。`WebSubjectFactory`创建Subject时是从Session中读取的认证状态和用户信息。所以我们需要对`WebSubjectFactory`中的`createSubject`方法进行重写，让其不依赖于Session而是依赖于Http Header。

# 用户修改了密码怎么办？
我们一般期望用户修改密码后，在线的用户需要重新登录。特别是移动端，如果用户修改完密码之后还可以使用`refreshToken`登录，这会有很大的安全隐患。

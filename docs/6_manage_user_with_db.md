# 使用数据库管理用户

---

> **导读**
>
> 本章主要实现从数据库中获取用户信息，并且用户密码使用MD5加密，并且在登录时使用验证码，以及更负责的密码错误$n$次之后启用验证码。

MyBatis的配置以及`mybatis-generator-maven-plugin`的使用不是本教程的内容，您可以在<https://gitee.com/jaune/spring-boot-shiro>查看相关代码。

# 从数据库中获取用户信息

## User表
```sql
create table sys_user (
  user_id VARCHAR(64) PRIMARY KEY COMMENT '用户ID',
  username VARCHAR(64) BINARY COMMENT '用户名',
  password VARCHAR(64) COMMENT '密码',
  phone_number VARCHAR(64) COMMENT '电话号码',
  last_login_time DATETIME COMMENT '最后一次登录时间',
  state TINYINT COMMENT '1-正常，2-锁定，3-停用' DEFAULT 1,
  create_time DATETIME COMMENT '创建时间'
)

insert into sys_user VALUES ('1', 'admin', '123456', '13600000000', null, 1, CURDATE());
```
您可以在项目源码的`src/main/resource/database/create_user.sql`下找到此代码。

生成的用户相关的类如下
- `com.codestd.security.model.SysUser`
- `com.codestd.security.mapper.SysUserMapper`
- `src/main/resouces/mapper/SysUserMapper.xml`

这里先使用明文密码，在介绍到使用MD5加密密码的时候再改为MD5密文。

## 增加根据用户名和手机号获取用户的方法

因为现在基本上都是用户名和手机号可以同时使用。用些网站是直接使用手机号或邮箱登录的，实现方法与下面要说的类似。·


```java
// SysUserMapper
/**
 * 通过用户名或手机号查询用户信息
 * @param searchKey 手机号或用户名
 * @return 如果没有查找到返回null
 */
SysUser findByUsernameOrPhoneNumber(String searchKey);


```
```xml
<!-- SysUserMapper.xml -->

<select id="findByUsernameOrPhoneNumber" resultType="com.codestd.security.model.SysUser">
    select * from sys_user where username = #{searchKey} or phone_number = #{searchKey}
</select>
```

> MySql 在做字符串匹配的时候是不区分大小写的。假如我们数据库中的username为`admin`，我们使用SQL语句`select * from sys_user where username = 'Admin'`也是能匹配到我们的用户的。如果要区分大小写则需要在建表的时候使用`Binary`标识敏感属性。所以我们再建表的时候在`username`后面增加`Binary`标识。

## 自定义Realm
添加一个自定义的Realm`com.codestd.security.shiro.realm.DatabaseRealm`，继承自`org.apache.shiro.realm.AuthorizingRealm`。一般自定义的Realm都继承自`AuthorizingRealm`。

```java
import com.codestd.security.mapper.SysUserMapper;
import com.codestd.security.model.SysUser;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 自定义凭证处理
 *
 * @author Wang Chengwei(Jaune)
 * @since 1.0.0
 */
public class DatabaseRealm extends AuthorizingRealm {

    @Autowired
    private SysUserMapper sysUserMapper;
    /**
     * 角色权限处理
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        SysUser user = (SysUser) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        if ("admin".equals(user.getUsername())) {
            authorizationInfo.addRole("admin");
        }
        return authorizationInfo;
    }

    /**
     * 用户身份信息
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
        SysUser user = this.sysUserMapper.findByUsernameOrPhoneNumber(usernamePasswordToken.getUsername());

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

        return new SimpleAuthenticationInfo(user, user.getPassword(), user.getUsername());
    }
}

```

继承自抽象类`AuthorizingRealm`，需要实现两个方法。
```java
protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals);

protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException;
```

- `doGetAuthorizationInfo`这个是获取权限信息的，用户的角色信息和权限信息需要在这个方法中返回。在下一章将详细介绍这个方法的使用。本章只是简单的根据用户名判断，如果是`admin`则添加`admin`角色。一般这里是要从数据库中获取用户信息的。
- `doGetAuthenticationInfo`这里就是用户认证信息的处理，一般在这个方法中获取用户信息，并判断用户状态。

## 配置修改
将`ShiroConfiguration`中`SimpleAccountRealm`的配置改为`DatabaseRealm`

```java
@Bean
public DatabaseRealm realm() {
    SimpleAccountRealm accountRealm = new SimpleAccountRealm();
    accountRealm.addAccount("user1", "123456");
    accountRealm.addAccount("admin", "123456", "admin");
    return accountRealm;
}

@Bean
public DatabaseRealm realm() {
    return new DatabaseRealm();
}
```

## 调试
启动项目，进入到登录页面。先使用一个不存在的用户登录`admin1`，可以看到已经有了`用户名不存在!`的错误提示.
![](https://images.jaune162.com/images/shiro/6/1.png)

再输入正确的用户名和密码，能够正常进入到系统中。

然后将用户状态修改为`2`，重新登录。
```sql
update sys_user set state = 2 where user_id = '1';
```
![](https://images.jaune162.com/images/shiro/6/2.png)
得到正确提示，证明我们的配置已经生效。

将用户状态修改为正常，然后重新登录，并访问`http://localhost:8081/role`。能够正常进入到页面中，证明我们的角色配置也是正常的。

# 使用MD5加密密码

将密码修改为MD5密文`update sys_user set password = 'e10adc3949ba59abbe56e057f20f883e' where user_id = '1';`。

增加MD5密码匹配器`com.codestd.security.shiro.matcher.Md5CredentialsMatcher`

```java
public class Md5CredentialsMatcher implements CredentialsMatcher {

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        String dbPassword = (String) info.getCredentials();
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
        String encryptPassword = DigestUtils.md5Hex(new String(usernamePasswordToken.getPassword()));
        return dbPassword.equals(encryptPassword);
    }
}
```
这里的`DigestUtils`是***Apache Commons Codec***中提供的工具类。需要在Pom中增加下面的依赖。
```xml
<!-- https://mvnrepository.com/artifact/commons-codec/commons-codec -->
<dependency>
    <groupId>commons-codec</groupId>
    <artifactId>commons-codec</artifactId>
    <version>1.11</version>
</dependency>
```
然后修改`ShiroConfiguration`中的`DatabaseRealm`，使用`Md5CredentialsMatcher`替换掉默认的凭证匹配器。
```java
@Bean
public DatabaseRealm realm() {
    DatabaseRealm realm = new DatabaseRealm();
    realm.setCredentialsMatcher(new Md5CredentialsMatcher());
    return realm;
}
```
到此使用数据库维护用户信息的功能已经基本实现。

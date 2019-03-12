# 使用注解控制权限

---

# 启用Shiro注解
在`ShiroConfiguration`中增加下列配置。
```java
@Bean
public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
    return new LifecycleBeanPostProcessor();
}

@Bean
public AuthorizationAttributeSourceAdvisor  authorizationAttributeSourceAdvisor(
        @Qualifier("securityManager") DefaultWebSecurityManager securityManager) {
    AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
    advisor.setSecurityManager(securityManager);
    return advisor;
}
```
文档中配置了一个`DefaultAdvisorAutoProxyCreator` Bean，在SpringBoot项目中是不用配置的，因为SpringBoot会在启动的时候自动配置。

`LifecycleBeanPostProcessor`从Bean名称看应该是Bean生命周期处理的类，具体作用官方文档中也没有说。

配置完`LifecycleBeanPostProcessor`后，`ShiroConfiguration`中的`SystemSettings`无法注入。
```
@Autowired 
private SystemSettings systemSettings;
```
所以在`ShiroFilterFactoryBean`中使用的时候会报错，应该是跟Spring冲突导致的。写法需要改一下。去掉上面的属性注入，改为参数注入。
```java
@Bean("shiroFilter")
public ShiroFilterFactoryBean shiroFilter(
        @Qualifier("securityManager") DefaultWebSecurityManager securityManager,
        @Qualifier("sysResourceMapper") SysResourceMapper sysResourceMapper,
        @Qualifier("logoutFilter") LogoutFilter logoutFilter,
        @Autowired SystemSettings systemSettings, // 这里这样写，用@Qualifier也会报错
        @Qualifier("authenticationFilter") FormAuthenticationFilter authenticationFilter) {
    // ...
}
```

# 注解说明
Shiro提供的权限控制注解可以用在类上或方法上，可以在类中使用也可以在接口中使用。一共有5个，如下：
- **@RequiresPermissions: **配置访问方法所需的权限，使用方法：`@RequiresPermissions(value = {"perm001", "perm002"}, logical = Logical.OR)`，这里的`logical`表示多个权限的逻辑关系，可以是`OR`或`AND`，也就是拥有其中一个就可以访问或需要拥有所有权限才可以访问。默认是`AND`。
- **@RequiresRoles: **配置访问方法所需的角色，使用方法与`@RequiresPermissions`类似。
- **@RequiresUser: **Subject是`remembered`或`authenticated`都可以访问。相当于`shiroFilter`中`/test=user`的配置。可参考：`org.apache.shiro.web.filter.authc.UserFilter`。
- **@RequiresAuthentication: **Subject是`authenticated`状态，也就是调用`subject.isAuthenticated()`返回值为`true`，相当于`/test=authc`
- **@RequiresGuest: **游客即可访问。相当于`anon`

注解的处理和filter是不一样的，注解是不经过filter的，所以还是存在一定的区别的。比如`Permissions`在filter中就不能配置权限之间的逻辑关系。而且如果权限不足注解的方式是直接抛出`AuthorizationException`异常。

An authenticated user is a Subject that has successfully logged in (proven their identity) during their current session.
A remembered user is any Subject that has proven their identity at least once, although not necessarily during their current session, and asked the system to remember them.

# 使用
创建测试Service
```java
public interface AnnotationService {

    @RequiresRoles(value = {"user"}, logical = Logical.OR)
    String test();
}

@Service
public class AnnotationServiceImpl implements AnnotationService {

    @Override
    public String test() {
        return "Annotation Test";
    }
}
```

创建测试Controller
```java
@RestController
public class AnnotationController {

    @Autowired
    private AnnotationService annotationService;

    @GetMapping("/annotation")
    public String test() {
        return this.annotationService.test();
    }
}
```


使用`user`用户登录，访问`/annotation`。可以正常访问。
![](https://images.jaune162.com/images/shiro/12/1.png)

使用`guest`登录，然后访问`/annotation`。报异常
![](https://images.jaune162.com/images/shiro/12/2.png)

这个异常可以由Spring拦截后统一处理，Spring异常处理不是本教程讲的范围，所以本文中不再赘述。请参考Spring官方文档。

- <https://docs.spring.io/spring/docs/5.0.8.RELEASE/spring-framework-reference/web.html#mvc-exceptionhandlers>
- <https://docs.spring.io/spring/docs/5.0.8.RELEASE/spring-framework-reference/web.html#mvc-ann-exceptionhandler>

# RolePermissionResolver
因为我们的角色和权限是分开的，比如用户拥有权限`p1`，拥有角色`r1`，而角色`r1`包含`p2,p3`。那么我们设置到`AuthorizationInfo`中的角色和权限是
```
roles=[r1]
permissions=[p1]
```

这时如果我们给方法设置需要`p2`才能访问，那么就会出现用户虽然拥有权限，但是无法访问的问题，所以我们要让`Shiro`知道角色和权限的对应关系。让`Shiro`能够通过角色找到用户的权限。所以在这里我们要用到`org.apache.shiro.authz.permission.RolePermissionResolver`。这时一个接口。

```java
public interface RolePermissionResolver {
    Collection<Permission> resolvePermissionsInRole(String roleString);
}
```

```java
/**
 * 通过角色获取权限
 *
 * @author Wang Chengwei(Jaune)
 * @since 1.0.0
 */
public class MemoryRolePermissionResolver implements RolePermissionResolver, InitializingBean {

    private PermissionResolver permissionResolver = new WildcardPermissionResolver();
    private SysRoleMapper sysRoleMapper;
    private Map<String, List<Permission>> rolePermissionsMapping = new HashMap<>();

    public void setSysRoleMapper(SysRoleMapper sysRoleMapper) {
        this.sysRoleMapper = sysRoleMapper;
    }

    @Override
    public Collection<Permission> resolvePermissionsInRole(String roleString) {
        return this.rolePermissionsMapping.get(roleString);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        this.resetMapping();
    }

    /**
     * 从数据库中读取权限资源对应关系
     */
    private void resetMapping() {
        List<SysRole> sysRoles = this.sysRoleMapper.findRolePermissionsMapping();
        for (SysRole sysRole : sysRoles) {
            List<Permission> permissions = this.rolePermissionsMapping.computeIfAbsent(sysRole.getRoleMark(),
                    o -> new ArrayList<>());
            permissions.add(this.permissionResolver.resolvePermission(sysRole.getPermissionMark()));
        }
    }

    /**
     * 提供一个refresh方法用户更新{@link #rolePermissionsMapping}中缓存的数据。
     */
    public void refresh() {
        this.resetMapping();
    }
}
```

将`MemoryRolePermissionResolver`配置到`Realm`中。

```java
@Bean
public MemoryRolePermissionResolver rolePermissionResolver(
        @Qualifier("sysRoleMapper")SysRoleMapper sysRoleMapper) {
    MemoryRolePermissionResolver rolePermissionResolver = new MemoryRolePermissionResolver();
    rolePermissionResolver.setSysRoleMapper(sysRoleMapper);
    return rolePermissionResolver;
}

/**
 * 凭证管理
 */
@Bean
public DatabaseRealm realm(@Qualifier("ehCacheManager") CacheManager cacheManager,
                           @Qualifier("rolePermissionResolver") RolePermissionResolver rolePermissionResolver) {
    DatabaseRealm realm = new DatabaseRealm();
    // ...
    realm.setRolePermissionResolver(rolePermissionResolver);
    return realm;
}
```

> 源码：<https://gitee.com/jaune/spring-boot-shiro/tree/V2.0.5>

# 参考资料：
[1] Shiro官方文档#启用Shiro注解(<http://shiro.apache.org/spring.html#enabling-shiro-annotations>)

# 使用数据库管理权限（2）

---

> **本章主要学什么？**
>
>  1. Shiro 在初始化的时候如何从数据库载入资源，及资源对应的权限角色信息。
>  2. 用户登录时，如何从数据库中读取用户的权限及资源信息。


# 资源配置格式说明

Shiro的资源配置格式为`filterChainName[pathConfig1,pathConfig2,...]`，例如角色过滤器，`filterChainName`为`roles`，那么配置`roles[admin,user]`，意思就是这个资源可以让拥有`admin`或者`user`角色的用户访问。权限的`filterChainName`为`perms`，这些都是固定的（当然也可以自定义，在下一章将自义定的权限过滤器时会说到）。

![](https://images.jaune162.com/images/shiro/10/1.png)

```
/res001=roles[admin,guest],perms[res001]
/res001=roles[admin,guest]
/res003=perms[res001]
```

所以我们需要在`ShiroFilterFactoryBean`将`filterChainDefinitionMap`配置成上面的形式（这里的例子与实际我们要处理的数据无关，只是举个例子）。

Shiro验证权限和角色是采用的严格模式，也就是说如果我们设置的资源的访问权限是`roles[admin,guest],perms[res001]`，那么用户需要同时具有`admin`、`guest`两个角色，且拥有`res001`权限才能访问。但是在实际项目中我们一般是期望满足一个就可以访问。所以还需要对`Shiro`的过滤器进行扩展。

在本实例中，通过一种变通的方式处理。**只使用权限，不使用角色**。资源和权限对应，然后用户通过角色和权限对应。再修改`PermissionsAuthorizationFilter`权限验证的方式，同样可以达到目的。

# 添加测试资源
```java
@RestController
public class ResourceController {

    @GetMapping("/res001") public String res001() {return "res001";}
    @GetMapping("/res002") public String res002() {return "res002";}
    @GetMapping("/res003") public String res003() {return "res003";}
    @GetMapping("/res004") public String res004() {return "res004";}
    @GetMapping("/res005") public String res005() {return "res005";}
    @GetMapping("/res006") public String res006() {return "res006";}
    @GetMapping("/res007") public String res007() {return "res007";}
    @GetMapping("/res008") public String res008() {return "res008";}
}
```
# 动态设置filterChainDefinitionMap

定义`DynamicShiroFilterFactoryBean`继承自`ShiroFilterFactoryBean`，然后重写`setFilterChainDefinitionMap`方法，因为一部分资源需要手动配置，所以在配置勒种配置`filterChainDefinitionMap`的功能还要保留。

```java
public class DynamicShiroFilterFactoryBean extends ShiroFilterFactoryBean {

    private static Logger logger = LoggerFactory.getLogger(DynamicShiroFilterFactoryBean.class);
    // 不能使用@Autowired，会出现无法注入的问题。
    private SysResourceMapper sysResourceMapper;

    private Map<String, String> manualFilterChainDefinitionMap;

    public void setSysResourceMapper(SysResourceMapper sysResourceMapper) {
        this.sysResourceMapper = sysResourceMapper;
    }

    @Override
    public void setFilterChainDefinitionMap(Map<String, String> filterChainDefinitionMap) {
        // 刷新资源时使用
        this.manualFilterChainDefinitionMap = filterChainDefinitionMap;
        this.setFilterChainDefinitionMap();
    }
    
    private void setFilterChainDefinitionMap() {
        
        Map<String, String> mergedFilterChainDefinitionMap = new LinkedHashMap<>();
        Map<String, FilterChainDefinitionMap> databaseFilterChainDefinitionMap = new LinkedHashMap<>();

        List<SysResource> resourcePermissions = this.sysResourceMapper.findResourcePermissionMap();
        for (SysResource resourcePermission : resourcePermissions) {
            FilterChainDefinitionMap filterChainDefinitionMap =
                    databaseFilterChainDefinitionMap.computeIfAbsent(resourcePermission.getResourceUrl(), o -> new FilterChainDefinitionMap());
            filterChainDefinitionMap.addPermission(resourcePermission.getPermissionMark());
        }

        for (Map.Entry<String, FilterChainDefinitionMap> entry : databaseFilterChainDefinitionMap.entrySet()) {
            mergedFilterChainDefinitionMap.put(entry.getKey(), entry.getValue().getChainDefinition());
        }

        // 添加配置文件中配置的filterChainDefinitionMap
        for (Map.Entry<String, String> entry : this.manualFilterChainDefinitionMap.entrySet()) {
            mergedFilterChainDefinitionMap.put(entry.getKey(), entry.getValue());
        }
        
        super.setFilterChainDefinitionMap(mergedFilterChainDefinitionMap);
    }

	// 将权限拼接成perms[xxx,xxx]的形式
    static class FilterChainDefinitionMap {
        private Set<String> permissions = new HashSet<>();

        void addPermission(String permission) {
            if (!this.permissions.contains(permission)) {
                this.permissions.add(permission);
            }
        }

        String getChainDefinition() {
            StringBuilder sb = new StringBuilder();
            if (this.permissions.size() > 0) {
                sb.append("perms[")
                        .append(StringUtils.arrayToDelimitedString(this.permissions.toArray(), ","))
                        .append("]");
            }

            return sb.toString();
        }
    }
}

```

在`SysResourceMapper`中增加`findResourcePermissionMap`用户获取资源和权限的对应关系。SQL语句前面已经写过，此处省略这个方法的代码。

# 从数据库读取用户权限
修改`DatabaseRealm`中的`doGetAuthorizationInfo`方法，改为从数据库中读取资源。在这个方法中不需要缓存用户权限数据，前面我们已经配置过缓存，Shiro会自己做这件事。

```java
/**
 * 角色权限处理
 */
@Override
protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    SysUser user = (SysUser) principals.getPrimaryPrincipal();
    SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
    if (user != null) {
        List<String> permissions = this.sysUserMapper.getPermissions(user.getUserId());
        for (String permission : permissions) {
            authorizationInfo.addStringPermission(permission);
        }
    }
    return authorizationInfo;
}
```

获取用户权限的SQL在前面已经提供，所以此处省略`sysUserMapper.getPermissions`的代码。

# 自定义PermissionsAuthorizationFilter
```java
public class CodestdPermissionsAuthorizationFilter extends AuthorizationFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        Subject subject = getSubject(request, response);
        String[] perms = (String[]) mappedValue;
        boolean isPermitted = false;
        if (perms != null && perms.length > 0) {
            for (String perm : perms) {
                if (subject.isPermitted(perm)) {
                    isPermitted = true;
                    break;
                }
            }
        } else {
            isPermitted = true;
        }
        return isPermitted;
    }
}
```
在原来的`PermissionsAuthorizationFilter`中，使用的是`subject.isPermittedAll(perms)`校验的权限，这个方法只有在用户拥有所有`perms`中的所有权限时才会返回`true`。

# 修改ShiroFilterFactoryBean配置
将`ShiroFilterFactoryBean`改为`DynamicShiroFilterFactoryBean`。

```java
@Bean("shiroFilter")
public ShiroFilterFactoryBean shiroFilter(
        @Qualifier("securityManager") DefaultWebSecurityManager securityManager,
        @Qualifier("sysResourceMapper") SysResourceMapper sysResourceMapper,
        @Qualifier("logoutFilter") LogoutFilter logoutFilter,
        @Qualifier("authenticationFilter") FormAuthenticationFilter authenticationFilter) {
    DynamicShiroFilterFactoryBean shiroFilterFactoryBean = new DynamicShiroFilterFactoryBean();
    shiroFilterFactoryBean.setSysResourceMapper(sysResourceMapper);
    shiroFilterFactoryBean.setSecurityManager(securityManager);
    shiroFilterFactoryBean.setLoginUrl("/login");
    shiroFilterFactoryBean.setSuccessUrl(this.systemSettings.getLoginSuccessUrl());

    Map<String, Filter> filterMap = new LinkedHashMap<>();
    filterMap.put("logout", logoutFilter);
    filterMap.put("authc", authenticationFilter);
    filterMap.put("perms", new PermissionsAuthorizationFilter());
    shiroFilterFactoryBean.setFilters(filterMap);
    Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
    filterChainDefinitionMap.put("/favicon.ico", "anon");
    // ... 中间部分省略
    filterChainDefinitionMap.put("/**", "authc");
    shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
    return shiroFilterFactoryBean;
}
```

`SysResourceMapper`要在这里注入，如果在`DynamicShiroFilterFactoryBean`中使用`@Autowired`会因为加载顺序的问题导致无法注入。

配置完之后重启就可以进行测试了。源码位置：<https://gitee.com/jaune/spring-boot-shiro/tree/V2.0.3>

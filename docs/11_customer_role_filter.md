# 自定义角色权限过滤器

---

> 上节说到，Shiro对于权限的验证采用的是严格模式，如果对于一个资源同时配置了角色和权限，那么用户必须同时有对应的角色和权限才能访问，而且没有可以配置的地方。

既然自定义那就再用Shiro提供的权限和角色过滤器了。因为在过滤器中先执行权限过滤器，如果权限过滤器验证不通过就直接阻止了，跳到了401页面。而权限过滤器验证通过了，还会进入到角色验证过滤器，如果这时候角色过滤器没有验证通过，那么同样会阻止访问。

这里我们自定义一个过滤器，`filterChainName`为`auth`，权限或角色配置通过`PERM_`和`ROLE_`前缀来区分，`PERM_`表示权限，`ROLE_`表示角色。例如`auth[PERM_perm001,ROLE_admin]`，表示访问这个页面需要`perm001`权限或`admin`角色。

# 自定义角色权限过滤器
```java
/**
 * 自定义角色权限过滤器，auth[PERM_perm001,ROLE_admin]
 *
 * @author Wang Chengwei(Jaune)
 * @since 1.0.0
 */
public class RolePermissionAuthorizationFilter extends AuthorizationFilter {

    // 增加权限和角色前缀的配置，好让我们能够从前缀区分权限和角色，从而调用对应的方法去做验证
    static final String DEFAULT_PERMISSION_PREFIX = "PERM_";
    static final String DEFAULT_ROLE_PREFIX = "ROLE_";

    // 启用严格模式
    private boolean strict;

    public void setStrict(boolean strict) {
        this.strict = strict;
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
		// 拆分角色和权限，将角色和权限分组
        RolePermissionSegregator sgregator = new RolePermissionSegregator(DEFAULT_PERMISSION_PREFIX, DEFAULT_ROLE_PREFIX, mappedValue);
        if (sgregator.isEmpty()) {
            return true;
        }
        Subject subject = getSubject(request, response);
        if (strict) {
            return strictCheck(subject, sgregator);
        } else {
            for (String role : sgregator.getRoles()) {
                if (subject.hasRole(role)) {
                    return true;
                }
            }

            for (Permission permission : sgregator.getPermissions()) {
                if (subject.isPermitted(permission)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean strictCheck(Subject subject, RolePermissionSegregator sgregator) {
        if (!sgregator.getPermissions().isEmpty()) {
            if (sgregator.getPermissions().size() == 1) {
                if (!subject.isPermitted(sgregator.getPermissions().get(0))) {
                    return false;
                }
            } else {
                if (!subject.isPermittedAll(sgregator.getPermissions())) {
                    return false;
                }
            }
        }

        // 这里可以直接return，因为后面没有条件判断了
        if (!sgregator.getRoles().isEmpty()) {
            if (sgregator.getRoles().size() == 1) {
                return subject.hasRole(sgregator.getRoles().get(0));
            } else {
                return subject.hasAllRoles(sgregator.getRoles());
            }
        }
        return true;
    }

    /**
     * 处理角色和权限，按照前缀将角色和权限分组
     */
    private static class RolePermissionSegregator {
        private List<String> roles = new ArrayList<>();
        private List<Permission> permissions = new ArrayList<>();
        private PermissionResolver permissionResolver = new WildcardPermissionResolver();

        private String permissionPrefix;
        private String rolePrefix;

        RolePermissionSegregator(String permissionPrefix, String rolePrefix, Object mappedValue) {
            this.permissionPrefix = permissionPrefix;
            this.rolePrefix = rolePrefix;
            this.init(mappedValue);
        }

        List<String> getRoles() {
            return roles;
        }

        List<Permission> getPermissions() {
            return permissions;
        }

        boolean isEmpty() {
            return this.roles.isEmpty() && this.permissions.isEmpty();
        }

        private void init(Object mappedValue) {
            String[] perms = (String[]) mappedValue;
            for (String perm : perms) {
                if (perm.startsWith(this.rolePrefix)) {
                    this.roles.add(perm.replace(this.rolePrefix, ""));
                } else if (perm.startsWith(this.permissionPrefix)) {
                    Permission permission = this.permissionResolver.resolvePermission(perm.replace(this.permissionPrefix, ""));
                    this.permissions.add(permission);
                }
            }
        }
    }
}

```

在这个过滤其中提供了`严格模式`和`宽松模式`,这只是一个例子，大家可以根据自己需求来实现自己的需求。

# 修改`DynamicShiroFilterFactoryBean`
修改`DynamicShiroFilterFactoryBean`改为资源同时和权限及角色映射。

首先修改内部类`FilterChainDefinitionMap`
```java
static class FilterChainDefinitionMap {
    private Set<String> auths = new HashSet<>();

    void addPermission(String permission) {
        String newPermission = RolePermissionAuthorizationFilter.DEFAULT_PERMISSION_PREFIX + permission;
        this.auths.add(newPermission);
    }
    void addRole(String role) {
        String newRole = RolePermissionAuthorizationFilter.DEFAULT_ROLE_PREFIX + role;
        this.auths.add(newRole);
    }

    String getChainDefinition() {
        if (this.auths.isEmpty()) {
            return null;
        }
        return "auth[" + StringUtils.arrayToDelimitedString(this.auths.toArray(), ",") + "]";
    }
}
```

`sysResourceMapper`中增加获取资源对应的角色的方法`findResourceRoleMap`，SQL语句前面已经提供，此处省略代码。

修改`setFilterChainDefinitionMap`方法。

```java
private void setFilterChainDefinitionMap() {
    
    Map<String, String> mergedFilterChainDefinitionMap = new LinkedHashMap<>();
    Map<String, FilterChainDefinitionMap> databaseFilterChainDefinitionMap = new LinkedHashMap<>();

    List<SysResource> resourcePermissions = this.sysResourceMapper.findResourcePermissionMap();
    for (SysResource resourcePermission : resourcePermissions) {
        FilterChainDefinitionMap filterChainDefinitionMap =
                databaseFilterChainDefinitionMap.computeIfAbsent(resourcePermission.getResourceUrl(), o -> new FilterChainDefinitionMap());
        filterChainDefinitionMap.addPermission(resourcePermission.getPermissionMark());
    }

	//+++++++++++++++++++++++++++++
    List<SysResource> resourceRoles = this.sysResourceMapper.findResourceRoleMap();
    for (SysResource resourceRole : resourceRoles) {
        FilterChainDefinitionMap filterChainDefinitionMap =
                databaseFilterChainDefinitionMap.computeIfAbsent(resourceRole.getResourceUrl(), o -> new FilterChainDefinitionMap());
        filterChainDefinitionMap.addRole(resourceRole.getRoleMark());
    }
    //+++++++++++++++++++++++++++++

    for (Map.Entry<String, FilterChainDefinitionMap> entry : databaseFilterChainDefinitionMap.entrySet()) {
        mergedFilterChainDefinitionMap.put(entry.getKey(), entry.getValue().getChainDefinition());
    }

    // 添加配置文件中配置的filterChainDefinitionMap
    for (Map.Entry<String, String> entry : this.manualFilterChainDefinitionMap.entrySet()) {
        mergedFilterChainDefinitionMap.put(entry.getKey(), entry.getValue());
    }
    
    super.setFilterChainDefinitionMap(mergedFilterChainDefinitionMap);
}
```

# 修改`DatabaseRealm`将用户权限也添加到`AuthorizationInfo`

`SysUserMapper`中增加一个获取用户权限的方法`getRoles`用户获取用户角色，`getPermissions`方法改为不再获取用户所有权限（即包含用户角色对应的权限），改为只获取用户权限表中的用户权限。

```java
@Override
protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    SysUser user = (SysUser) principals.getPrimaryPrincipal();
    SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
    if (user != null) {
        List<String> permissions = this.sysUserMapper.getPermissions(user.getUserId());
        for (String permission : permissions) {
            authorizationInfo.addStringPermission(permission);
        }
		//+++++++++++++++++++++++++++++
        List<String> roles = this.sysUserMapper.getRoles(user.getUserId());
        for (String role : roles) {
            authorizationInfo.addRole(role);
        }
        //+++++++++++++++++++++++++++++
    }
    return authorizationInfo;
}
```

# 将自定义过滤器配置到`ShiroFilterFactoryBean`中

```java
Map<String, Filter> filterMap = new LinkedHashMap<>();
filterMap.put("logout", logoutFilter);
filterMap.put("authc", authenticationFilter);
filterMap.put("auth", new RolePermissionAuthorizationFilter());
shiroFilterFactoryBean.setFilters(filterMap);
```
这里配置的`auth`要与`FilterChainDefinitionMap`中的一致。本实例源码：<https://gitee.com/jaune/spring-boot-shiro/tree/V2.0.4>

> 这里只是提供一种自定义过滤器实现权限控制的方法，各位读者如果想要用在项目中的话还请仔细考量，因为项目中的权限控制会更加复杂，可能会涉及到菜单的控制，页面按钮控制等。

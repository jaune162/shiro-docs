# 资源刷新

---

因为现在的资源和权限角色的对应关系也就是`FilterChainDefinitionMap`是在系统初始化的时候加载的，所以如果系统中的资源或权限发生变更，那么需要重启服务才能生效。这是极不合理的，所以我们需要在资源或权限发生变更的时候刷新`FilterChainDefinitionMap`，使变更后的权限立即生效。

那么是不是我们只要改变`FilterChainDefinitionMap`中的数据就可以了呢？请忘下看。

# 深入FilterChainDefinitionMap

让我们再回到`SpringShiroFilter`创建的起点---`ShiroFilterFactoryBean#createInstance()`。看其中的这段代码。

```java
FilterChainManager manager = createFilterChainManager();
PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();
chainResolver.setFilterChainManager(manager);
return new SpringShiroFilter((WebSecurityManager) securityManager, chainResolver);
```

可以看到`SpringShiroFilter`在初始化的时候，除了传入了`SecurityManager`之外，还传入了一个`PathMatchingFilterChainResolver`对象。而这个对象依赖于`FilterChainManager`，前面已经说过，这个对象是存的路径（资源）到filter的映射，以及其访问权限配置。此次我们重点关注`createFilterChainManager`方法。

```java
protected FilterChainManager createFilterChainManager() {

    DefaultFilterChainManager manager = new DefaultFilterChainManager();
    Map<String, Filter> defaultFilters = manager.getFilters();
    //apply global settings if necessary:
    for (Filter filter : defaultFilters.values()) {
        applyGlobalPropertiesIfNecessary(filter);
    }

    //Apply the acquired and/or configured filters:
    Map<String, Filter> filters = getFilters();
    if (!CollectionUtils.isEmpty(filters)) {
        for (Map.Entry<String, Filter> entry : filters.entrySet()) {
            String name = entry.getKey();
            Filter filter = entry.getValue();
            applyGlobalPropertiesIfNecessary(filter);
            if (filter instanceof Nameable) {
                ((Nameable) filter).setName(name);
            }
            //'init' argument is false, since Spring-configured filters should be initialized
            //in Spring (i.e. 'init-method=blah') or implement InitializingBean:
            manager.addFilter(name, filter, false);
        }
    }

    //build up the chains:
    Map<String, String> chains = getFilterChainDefinitionMap();
    if (!CollectionUtils.isEmpty(chains)) {
        for (Map.Entry<String, String> entry : chains.entrySet()) {
            String url = entry.getKey();
            String chainDefinition = entry.getValue();
            manager.createChain(url, chainDefinition);
        }
    }

    return manager;
}
```

因为filter不会动态改变，所以这里我们不关注filter，重点看`FilterChainDefinitionMap`处理的部分，也就是最后一段代码。
```java
Map<String, String> chains = getFilterChainDefinitionMap();
if (!CollectionUtils.isEmpty(chains)) {
    for (Map.Entry<String, String> entry : chains.entrySet()) {
        String url = entry.getKey();
        String chainDefinition = entry.getValue();
        manager.createChain(url, chainDefinition);
    }
}
```
这段代码遍历`FilterChainDefinitionMap`中的各项数据，然后调用了`manager.createChain`方法，重新处理的映射关系。顺便看下`createChain`方法中的核心代码。

```java
public void createChain(String chainName, String chainDefinition) {

	// "authc, roles[admin,user], perms[file:edit]" ---|to array|--> { "authc", "roles[admin,user]", "perms[file:edit]" }
    String[] filterTokens = splitChainDefinition(chainDefinition);

    for (String token : filterTokens) {
        String[] nameConfigPair = toNameConfigPair(token);
        addToChain(chainName, nameConfigPair[0], nameConfigPair[1]);
    }
}
```
是对`chainDefinition`拆分之后，又做的处理（具体的处理过程有兴趣的和研究下，我们本次的话题，代码看到这里就够了）。由此可见，这些过程都是在初始化的时候做的，而且`FilterChainDefinitionMap`的变更**不会对其造成影响**。
所以我们只能替换掉`SpringShiroFilter`实例中的`FilterChainResolver`对象才可以，并且我们需要重新创建`FilterChainManager`和`PathMatchingFilterChainResolver`。

# 实现刷新资源功能
既然知道了怎么处理，就看是写代码吧。

首先定义一个`ChainDefinitionRefreshable` 提供一个刷新方法。

```java
public interface ChainDefinitionRefreshable {

    /**
     * 刷新资源权限映射，重新从数据库中读取。
     */
    void refresh();
}
```

进入到我们的自定义ShiroFilterFactoryBean `DynamicShiroFilterFactoryBean`中，实现`ChainDefinitionRefreshable`接口。

```java
@Override
public void refresh() throws Exception {
    // 重新设置FilterChainDefinitionMap
    this.setFilterChainDefinitionMap();
    // FilterChainDefinitionMap中的内容已经发生变更，所以此时创建的FilterChainManager中是变更后的数据
    FilterChainManager manager = createFilterChainManager();
    PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();
    chainResolver.setFilterChainManager(manager);

    AbstractShiroFilter shiroFilter = (AbstractShiroFilter) this.getObject();
    if (shiroFilter != null) {
        shiroFilter.setFilterChainResolver(chainResolver);
    }
    logger.info("资源权限刷新成功。");
}
```
`getObject`方法用于获取创建的`shiroFilter`实例。代码如下

```java
public Object getObject() throws Exception {
    if (instance == null) {
        instance = createInstance();
    }
    return instance;
}
```

如果我们需要刷新资源，只需要注入`ChainDefinitionRefreshable`接口，然后调用`refresh`方法即可。

# 测试
添加一个新的资源
```java
@GetMapping("/res009") public String res009() {return "res009";}
```

添加一个刷新资源的控制器
```java
@RestController
public class RefreshController {

    @Autowired
    private ChainDefinitionRefreshable definitionRefreshable;

    @GetMapping("/refreshChain")
    public String refresh() throws Exception {
        this.definitionRefreshable.refresh();
        return "Success!!";
    }
}
```
使用`guest`账户登录，这是是可以放问的，因为`/res009`现在没有添加到权限控制中，任何登录的用户都可以访问。现在我们将`res009`设置成需拥有`perm001`权限才可以访问，然后访问`/refreshChain`刷新资源。

> `guest`用户没有`perm001`权限

```sql
insert into sys_resource values('RES009', 'RES009', '/res009', curdate());
insert into sys_permission_resource values ('009', 'PERM001', 'RES009');
```

然后再访问`res009`，此时因为权限信息已更新所以`guest`用户是不能访问的。

![](https://images.jaune162.com/images/shiro/13/1.png)

> 源码：<https://gitee.com/jaune/spring-boot-shiro/tree/V2.0.6>

# 课程简介

# 背景

公司项目（all-in-one的方式开发）采用的是前后端分离的方式，前端使用的是Vue。在设计之初并没有考虑要做成无状态服务，所以使用的是ProxyTable的方式可以让前端在调试接口的时候，实现前后端Session会话一致（具体实现后续文章会略作描述）。但是后来又要求开发安卓和IOS的客户端，如果重新写一套接口一个是时间来不及，一个是接口重复率达到了90%。所以在为了不影响前端项目使用的前提下，对接口服务做调整使其成为无状态服务，保证原来的权限控制仍然可用，并且支持移动端免登陆。

在此过程中积累并总结了一些经验，再结合之前使用shiro的一些经验，于是就有了本教程，在此希望能够帮助当初和我一样迷茫的同学。

# 实现目标

使用shiro实现RBAC权限控制，通过数据库读取资源信息及用户权限信息。并且同时支持PC端和移动端。

服务为无状态服务，支持分布式环境。

# 使用场景

- 常规项目（普通的All in one形式的Web项目）
- 前后端分离项目
- 移动端项目

课程采用循序渐进的模式，先从最简单的在常规项目中使用shiro讲起，然后讲shiro的一些原理知识。在了解了原理之后，再对原有功能进行改造，最终实现无状态的权限控制功能。

# 开发环境

- Java8+
- 开发工具：IntellJ IDEA 2018.x


# 课程定位

* 本课程为基础课程，没有Shiro基础也可以学习
* 适用于想做无状态服务权限控制的同学，课程仅提供Shiro的实现。后续会出其他实现方式的课程
* 同样适用于从有状态服务到无状态服务的无缝切换
* 本课程为基础课程，如果您是使用shiro的高手，本课程可能对您的帮助并不大。


# 相关技术

## SpringBoot

技能需求：熟悉 
简介：SpringBoot可以快速创建独立的服务，并且提供很多对于第三方的支持，而且配置非常简单。 

**特性：**
* 可以创建独立的Spring应用
* 内置Tomcat、Jetty、Undertow无需发布War包
* 提供大量的starterPOM，可简化Maven配置
* 支持自动配置（auto-configure）
* 提供指标、健康检查和外部配置等生产就绪（production-ready）功能
* 绝对没有代码生成并且没有XML配置文件

## Shiro

技能需求：了解 

>**简介：**
>Apache Shiro是一个强大且易用的Java安全框架,执行身份验证、授权、密码学和会话管理。使用Shiro的易于理解的API,您可以快速、轻松地获得任何应用程序,从最小的移动应用程序到最大的网络和企业应用程序。
><div style="text-align:right">（—-摘自百度百科）</div>

## JWT
**JWT** *(JSON Web Tokens)*，是一种协议。本质上是一种对Json数据进行加密、签名的技术。只不过Json数据有严格的格式定义（参见[RFC 7519](https://tools.ietf.org/html/rfc7519)）。借助JWT我们可以轻松实现Cookie Session。

可以从<https://jwt.io/>上了解JWT的更多信息。
我们在项目中使用的jwt jar包是[java-jwt](https://github.com/auth0/java-jwt)

## Redis
> Redis是一个key-value存储系统。和Memcached类似，它支持存储的value类型相对更多，包括string(字符串)、list(链表)、set(集合)、zset(sorted set --有序集合)和hash（哈希类型）。这些数据类型都支持push/pop、add/remove及取交集并集和差集及更丰富的操作，而且这些操作都是原子性的。在此基础上，redis支持各种不同方式的排序。与memcached一样，为了保证效率，数据都是缓存在内存中。区别的是redis会周期性的把更新的数据写入磁盘或者把修改操作写入追加的记录文件，并且在此基础上实现了master-slave(主从)同步。
> <div style="text-align:right">（—-摘自百度百科）</div>


## Spring Data Redis
Spring提供的一个可以方便的操作Redis缓存的库，借助这个库可以不用对Redis有很深入的了解也可以对Redis的数据进行操作。

# 学习方法

本课程建立在有状态（Session）服务之上，对有状态服务的过滤器、认证器等相关模块进行改造，最终实现有状态服务到无状态服务的无缝切换。 
在第二章会带领大家建立一套基于Shiro的有状态服务，我们将在这个服务的基础之上进行改造，中间会穿插对于源码的分析，之所以增加源码分析的部分，是因为了解源码将有助于我们理解Shiro的配置和各个组件的作用，以及如何更加友好的去扩展它们。

# 学习资料

- SpringBoot官方文档：<https://docs.spring.io/spring-boot/docs/2.0.3.RELEASE/reference/htmlsingle/>
- SpringBoot 1.5.4 中文版（由官方文档翻译）：<http://oopsguy.com/documents/springboot-docs/1.5.4/index.html>
- SpringBoot 2.0.0 中文版：<https://legacy.gitbook.com/book/docshome/springboot/details>、<https://github.com/DocsHome/springboot/> （如果觉得对您有帮助，请为作者star）
- Shiro官方文档：<https://shiro.apache.org/reference.html>
- JWT lib
    - jjwt文档及Github仓库地址：<https://github.com/jwtk/jjwt> 
    - java-jwt文档及Github仓库地址：<https://github.com/auth0/java-jwt>
- Redis官方文档：<https://redis.io/documentation>
- Spring-data-redis：<https://docs.spring.io/spring-data/redis/docs/2.0.8.RELEASE/reference/html/>

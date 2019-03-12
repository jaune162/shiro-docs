# Shiro快速开始指南

# Shiro的特性
- 易学，shiro的学习成本相对于`Spring Security`来说是比较低的。而且shiro的源码中类名、接口名和方法名的命名非常的规范并且容易理解的，仅通过类名或方法名就能判断这个类或者方法的功能（名称即注释）。
- 支持多种数据源JDBC、LDAP、ActiveDirectory等。
- 内置缓存支持，提供JVM内存和ehcache两种，只需简单配置即可启用缓存，如要需要支持其他缓存还可以自由扩展。
- 可以用于Web项目和非Web项目。并且可以支持分布式Session和单点登录（需要借助CAS）
- 提供丰富的过滤器，可轻松的应对各种使用场景。
- 提供注解及JSPTag支持，使权限控制更加灵活。

![Shiro 架构](https://images.jaune162.com/images/shiro/2/1.png)

# 项目创建

## Spring Boot 项目创建
这里我们使用`Spring Initializr`来创建项目。项目地址<https://start.spring.io/>。

项目管理工具支持：`Maven`和`Gradle`。

编程语言支持：`Java`、`Kotlin`和`Groovy`

在本例中我们使用IDEA提供的工具创建，具体步骤如下


1. `File` -> `New` -> `Project`，打开`New Project`对话框
![Alt text](https://images.jaune162.com/images/shiro/2/2.png)

2. `Project SDK`：选择JDK版本，`Choose Initializr Service URL.` 选择`Default`。点击`Next`进入项目设置对话框
![Alt text](https://images.jaune162.com/images/shiro/2/3.png)

3. 在这里设置项目的Group、Artifact、Version等信息，然后点击`Next`进入依赖选择对话框
![Alt text](https://images.jaune162.com/images/shiro/2/4.png)

4. 这里选择项目所依赖的一些包，具体如下

**Core**
`DevTools`,`Lombok`,`Configuration Processor`,`Cache`,`Aspects`

**Web**
`Web`

**Template Engines**
`Freemarker`

**SQL**
`MySql`,`JDBC`,`MyBatis`

**NoSQL**
`Redis`

![Alt text](https://images.jaune162.com/images/shiro/2/5.png)

对话框右侧的`Selected Dependencies`为当前选择的依赖。最后点击`Next`即可成功创建项目。创建成功后的项目结构如下
![Alt text](https://images.jaune162.com/images/shiro/2/6.png)

创建成功后的POM内容如下。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.codestd</groupId>
    <artifactId>spring-boot-shiro</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <packaging>jar</packaging>

    <name>spring-boot-shiro</name>
    <description>Demo project for Spring Boot and Apache Shiro</description>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.0.3.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
        <java.version>1.8</java.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-aop</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-cache</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-freemarker</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-jdbc</artifactId>
        </dependency>
        <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
            <version>1.3.2</version>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>

       <!-- 以下为可选项 -->
       <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>              
            </plugin>
        </plugins>
    </build>
</project>
```
在生成的Pom的基础上做了一些顺序调整，加了一点注释。

这里的`spring-boot-maven-plugin`插件配置需要注意。如果需要[在服务器中部署](https://docs.spring.io/spring-boot/docs/2.0.3.RELEASE/reference/htmlsingle/#deployment-install)，则需要修改配置为如下内容。
```xml
<plugin>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId>
    <configuration>
        <executable>true</executable>
    </configuration>
</plugin>
```
## 添加Shiro支持
在Pom中添加shiro依赖
```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.4.0</version>
</dependency>
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-ehcache</artifactId>
    <version>1.4.0</version>
</dependency>
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-cache</artifactId>
    <version>1.4.0</version>
</dependency>
```

在初期我们不需要使用数据库和Redis，所以可以先把相关的包注释。如下：
- `spring-boot-starter-jdbc`
- `mybatis-spring-boot-starter`
- `mysql-connector-java`
- `spring-boot-starter-data-redis`

## 部分依赖功能说明
- **DevTools：**提供项目热部署，需要做一些配置，不是本次课程的重点。
- **Lombok：**可以简化Bean开发，是一个在编译期生成`getter`、`setter`方法的工具，**需要借助`Lombok plugin`使用**。
- **Configuration Processor：**提供手动添加的配置文件在`application.<properties|yml>`中自动提示的功能，增加或修改配置属性时，需要执行`mvn complie`，才能自动提示。
- **shiro-ehcache：**缓存用户的权限信息时使用。

# 遇到的一些坑

### **SpringBoot项目在Linux中启动时出现`Unable to find Java`的错误**
这是因为环境变量的问题导致的，貌似在CentOS中SpringBoot启动时无法获取到环境变量中配置的Java环境。解决办法是创建一个Java的软链到`/usr/bin/`。
```powershell
ln -s <your_java_home>/bin/java /usr/bin/java 
```

!> 这里必须是绝对路径，比如您的JDK路径为`/opt/java1.8`，则命令应写为`ln -s /opt/java1.8/bin/java /usr/bin/java`


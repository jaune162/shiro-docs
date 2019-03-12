# 使用数据库管理权限（1）

---

# RBAC角色访问控制模型
这是一个简单的RBAC模型
![](https://images.jaune162.com/images/shiro/9/1.png)

- 资源可以是一个我们系统中提供的访问的地址，也可以是业务层的一个接口方法，或者是页面上的一个按钮（Shiro可以通过jspTag对页面上的资源进行权限控制）。

- 权限是资源的集合，一个权限可以有一个或多个资源组成。

- 角色是权限的集合，一个角色可以由一个或多个权限组成。

- 既可以为用户分配角色又可以为用户分配权限。本实例不考虑分配过程，如果用户可以同时拥有权限和角色的话，分配过程的复杂度会增加不少，这里只针对模拟数据讲述Shiro如何借助数据库实现对角色和权限的控制。

> 更复杂的RBAC还有角色继承、互斥角色、用户组等。这些不是Shiro处理的内容，所以不在本教程范围内。百度百科对[RBAC](https://baike.baidu.com/item/RBAC/1328788?fr=aladdin)有详细的描述

# 数据库设计
![](https://images.jaune162.com/images/shiro/9/2.png)

```sql
create table sys_resource (
  resource_id varchar(64) primary key comment '资源ID',
  resource_name varchar(64) comment '资源名称',
  resource_url varchar(200) comment '资源地址',
  create_time datetime comment '创建时间'
) comment '资源信息';

create table sys_permission (
  permission_id varchar(64) primary key comment '权限ID',
  permission_name varchar(64) comment '权限名称',
  permission_mark varchar(64) comment '权限标志，作为Shiro判定权限的标志',
  create_time datetime comment '创建时间'
) comment '权限信息';

create unique index uidx_permission_mark on sys_permission(permission_mark);

create table sys_permission_resource (
  id varchar(64) primary key ,
  permission_id varchar(64) comment '权限ID',
  resource_id varchar(64) comment '资源ID'
) comment '权限资源';

create table sys_role (
  role_id varchar(64) primary key comment '角色ID',
  role_name varchar(64) comment '权限名称',
  role_mark varchar(64) comment '权限标志',
  create_time datetime comment '创建时间'
) comment '角色信息';

create unique index uidx_role_mark on sys_role(role_mark);

create table sys_role_permission (
  id varchar(64) primary key ,
  role_id varchar(64) comment '角色ID',
  permission_id varchar(64) comment '权限ID'
) comment '角色权限';

create table sys_user_role(
  id varchar(64) primary key ,
  user_id varchar(64) comment '用户ID',
  role_id varchar(64) comment '用户角色'
) comment '用户角色';

create table sys_user_permission (
  id varchar(64) primary key ,
  user_id varchar(64) comment '用户ID',
  permission_id varchar(64) comment '权限ID'
) comment '用户角色';

```

## 数据准备
![](https://images.jaune162.com/images/shiro/9/3.png)

```sql
insert into sys_resource values('RES001', 'RES001', '/res001', curdate());
insert into sys_resource values('RES002', 'RES002', '/res002', curdate());
insert into sys_resource values('RES003', 'RES003', '/res003', curdate());
insert into sys_resource values('RES004', 'RES004', '/res004', curdate());
insert into sys_resource values('RES005', 'RES005', '/res005', curdate());
insert into sys_resource values('RES006', 'RES006', '/res006', curdate());
insert into sys_resource values('RES007', 'RES007', '/res007', curdate());
insert into sys_resource values('RES008', 'RES008', '/res008', curdate());

insert into sys_permission values ('PERM001', 'PERM001', 'perm001', curdate());
insert into sys_permission values ('PERM002', 'PERM002', 'perm002', curdate());
insert into sys_permission values ('PERM003', 'PERM003', 'perm003', curdate());
insert into sys_permission values ('PERM004', 'PERM004', 'perm004', curdate());

insert into sys_permission_resource values ('001', 'PERM001', 'RES001');
insert into sys_permission_resource values ('002', 'PERM001', 'RES002');
insert into sys_permission_resource values ('003', 'PERM002', 'RES003');
insert into sys_permission_resource values ('004', 'PERM002', 'RES004');
insert into sys_permission_resource values ('005', 'PERM003', 'RES005');
insert into sys_permission_resource values ('006', 'PERM003', 'RES006');
insert into sys_permission_resource values ('007', 'PERM004', 'RES007');
insert into sys_permission_resource values ('008', 'PERM004', 'RES008');

insert into sys_role values ('ROLE001', 'Admin', 'admin', curdate());
insert into sys_role values ('ROLE002', 'User', 'user', curdate());
insert into sys_role values ('ROLE003', 'Guest', 'guest', curdate());

insert into sys_role_permission values ('001', 'ROLE001', 'PERM001');
insert into sys_role_permission values ('002', 'ROLE001', 'PERM002');
insert into sys_role_permission values ('003', 'ROLE001', 'PERM003');
insert into sys_role_permission values ('004', 'ROLE001', 'PERM004');

insert into sys_role_permission values ('005', 'ROLE002', 'PERM001');
insert into sys_role_permission values ('006', 'ROLE002', 'PERM002');

insert into sys_role_permission values ('008', 'ROLE003', 'PERM003');

insert into sys_user values ('2', 'user', 'e10adc3949ba59abbe56e057f20f883e', null, null, 1, curdate());
insert into sys_user values ('3', 'guest', 'e10adc3949ba59abbe56e057f20f883e', null, null, 1, curdate());

insert into sys_user_role values ('001', '1', 'ROLE001');
insert into sys_user_role values ('002', '2', 'ROLE002');
insert into sys_user_role values ('003', '3', 'ROLE003');

insert into sys_user_permission values ('002', '2', 'PERM004');
insert into sys_user_permission values ('003', '3', 'PERM004');
```

## 比较重要的SQL

```sql
/* 获取资源对应的权限 */
select sr.resource_url, sp.permission_mark from sys_resource sr
LEFT JOIN sys_permission_resource spr on sr.resource_id = spr.resource_id
left join sys_permission sp on spr.permission_id = sp.permission_id;

/* 获取资源对应的角色 */
select sr.resource_url, srl.role_mark from sys_resource sr
LEFT JOIN sys_permission_resource spr on sr.resource_id = spr.resource_id
LEFT JOIN sys_role_permission srp on srp.permission_id = spr.permission_id
left join sys_role srl on srl.role_id = srp.role_id;

/* 获取用户的角色 */
select sr.role_mark from sys_user su
left join sys_user_role sur on su.user_id = sur.user_id
left join sys_role sr on sur.role_id = sr.role_id
where su.user_id = '2';

/* 获取用户的权限 */
select sp.permission_mark from sys_user su
left join sys_user_permission sup on su.user_id = sup.user_id
left join sys_permission sp on sp.permission_id = sup.permission_id
where su.user_id = '2';

/* 获取用户所有的权限，包括分配的角色对应的权限 */
select DISTINCT t.permission_mark from (
  select sp.permission_mark from sys_user su
      inner join sys_user_permission sup on su.user_id = sup.user_id
      left join sys_permission sp on sp.permission_id = sup.permission_id
  where su.user_id = '1'
  UNION ALL
  select sp.permission_mark from sys_user su
    inner join sys_user_role sur on su.user_id = sur.user_id
    left join sys_role_permission srp on sur.role_id = srp.role_id
    left join sys_permission sp on srp.permission_id = sp.permission_id
  where su.user_id = '1'
) t
```

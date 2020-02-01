# Spring Boot 整合shiro模拟前后端分离

## 加入全局异常监控

```java
package com.example.aspect;

import org.apache.shiro.authz.UnauthorizedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Kahen
 * @create 2020-02-01 11:13
 */
@RestControllerAdvice //以json串的形式返回出去
public class AppExceptionAdivse {
    @ExceptionHandler(value= {UnauthorizedException.class})
    public Map<String, Object> unauthorized() {
        Map<String, Object> map=new HashMap<>();
        map.put("code", 302);
        map.put("msg", "未授权");
        System.out.println("未授权");
        return map;
    }

}


```

## 创建LoginController

```java
package com.example.controller;

import com.example.common.ActiverUser;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 * @author kahen
 */
@RestController
@RequestMapping("login")
public class LoginController {



	/**
	 * 登陆
	 */
	@RequestMapping("login")
	public Map<String,Object> login(String username, String password, HttpSession session) {
		Map<String,Object> map=new HashMap<>();
		//封装token
		UsernamePasswordToken token=new UsernamePasswordToken(username, password);
		//得到主体
		Subject subject = SecurityUtils.getSubject();
		try {
			subject.login(token);
			ActiverUser activerUser = (ActiverUser) subject.getPrincipal();
			session.setAttribute("user", activerUser.getUser());
			map.put("code", 200);
			map.put("msg", "登陆成功");
			return map;
		} catch (AuthenticationException e) {
			e.printStackTrace();
			map.put("code", -1);
			map.put("msg", "登陆失败 用户名或密码不正确");
			return map;
		}
	}



}

```

## 创建UserController

```java
package com.example.controller;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author kahen
 */
@RestController
@RequestMapping("user")
public class UserController {


	@RequiresPermissions(value= {"user:query"})
	@RequestMapping("query")
	public Map<String,Object> query() {
		Map<String,Object> map=new HashMap<>();
		map.put("msg", "query");
		return map;
	}
	@RequiresPermissions(value= {"user:add"})
	@RequestMapping("add")
	public Map<String,Object> add() {
		Map<String,Object> map=new HashMap<>();
		map.put("msg", "add");
		return map;
	}
	@RequiresPermissions(value= {"user:update"})
	@RequestMapping("update")
	public Map<String,Object> update() {
		Map<String,Object> map=new HashMap<>();
		map.put("msg", "update");
		return map;
	}
	@RequiresPermissions(value= {"user:delete"})
	@RequestMapping("delete")
	public Map<String,Object> delete() {
		Map<String,Object> map=new HashMap<>();
		map.put("msg", "delete");
		return map;
	}
	@RequiresPermissions(value= {"user:export"})
	@RequestMapping("export")
	public Map<String,Object> export() {
		Map<String,Object> map=new HashMap<>();
		map.put("msg", "export");
		return map;
	}
}

```

## 创建ShiroLoginFilter

```java
package com.example.filter;

/**
 * @author Kahen
 * @create 2020-02-01 11:28
 */

import com.alibaba.fastjson.JSONObject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class ShiroLoginFilter extends FormAuthenticationFilter {

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        //if (isAjax(request)) {
        httpServletResponse.setCharacterEncoding("UTF-8");
        httpServletResponse.setContentType("application/json");
        Map<String, Object> resultData = new HashMap<>();
        resultData.put("code", -1);
        resultData.put("msg", "未登录!");
        httpServletResponse.getWriter().write(JSONObject.toJSON(resultData).toString());
   /* } else {
         // saveRequestAndRedirectToLogin(request, response);
         *//**
         * @Mark 非ajax请求重定向为登录页面
         *//*
         httpServletResponse.sendRedirect("/login.jsp");
      }*/
        return false;
    }

    private boolean isAjax(ServletRequest request) {
        String header = ((HttpServletRequest) request).getHeader("X-Requested-With");
        if ("XMLHttpRequest".equalsIgnoreCase(header)) {
            return Boolean.TRUE;
        }
        return Boolean.FALSE;
    }
}


```

## 修改pom.xml引入fastjson

```xml
<fastjson.version>1.2.60</fastjson.version>

<!-- https://mvnrepository.com/artifact/com.alibaba/fastjson -->
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>${fastjson.version}</version>
</dependency>

```

## 创建ShiroProperties

该项目有引入lombok插件

```java
package com.example.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Kahen
 * @create 2020-01-19 20:47
 */
@ConfigurationProperties(value = "shiro")
@Data
public class ShiroProperties {
    private String hashAlgorithmName = "md5";
    private Integer hashIterations = 2;
    private String loginUrl;
    private String unauthorizedUrl;
    private String[] anonUrls;
    private String logoutUrl;
    private String[] authUrls;
}

```



## 创建ShiroAutoConfiguration

```java
package com.example.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import com.example.filter.ShiroLoginFilter;
import com.example.realm.UserRealm;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Kahen
 * @create 2020-01-19 20:45
 */
@Configuration
@EnableConfigurationProperties(ShiroProperties.class)
public class ShiroAutoConfiguration {

    @Autowired
    private ShiroProperties shiroProperties;

    /**
     * 创建凭证匹配器
     */
    @Bean
    public HashedCredentialsMatcher credentialsMatcher() {
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName(shiroProperties.getHashAlgorithmName());
        credentialsMatcher.setHashIterations(shiroProperties.getHashIterations());
        return credentialsMatcher;
    }

    /**
     * 创建realm
     */
    @Bean
    public UserRealm userRealm(CredentialsMatcher credentialsMatcher) {
        UserRealm userRealm = new UserRealm();
        //注入凭证匹配器
        userRealm.setCredentialsMatcher(credentialsMatcher);
        return userRealm;
    }

    /**
     * 声明安全管理器
     */
    @Bean("securityManager")
    public SecurityManager securityManager(UserRealm userRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(userRealm);
        return securityManager;
    }


    /**
     * 配置过滤器 Shiro 的Web过滤器 id必须和web.xml里面的shiroFilter的 targetBeanName的值一样
     */
    @Bean("shiroFilter")
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        //注入安全管理器
        bean.setSecurityManager(securityManager);
        //注入登陆页面
        bean.setLoginUrl(shiroProperties.getLoginUrl());
        //注入未授权的页面地址
        bean.setUnauthorizedUrl(shiroProperties.getUnauthorizedUrl());
        //注入过滤器
        Map<String, String> filterChainDefinition = new HashMap<>();

        //注入放行地址
        if (shiroProperties.getAnonUrls() != null && shiroProperties.getAnonUrls().length > 0) {
            String[] anonUrls = shiroProperties.getAnonUrls();
            for (String anonUrl : anonUrls) {
                filterChainDefinition.put(anonUrl, "anon");
            }
        }
        //注入登出的地址
        if (shiroProperties.getLogoutUrl() != null) {
            filterChainDefinition.put(shiroProperties.getLogoutUrl(), "logout");
        }
        //注拦截的地址
        String[] authcUrls = shiroProperties.getAuthUrls();
        if (authcUrls != null && authcUrls.length > 0) {
            for (String authcUrl : authcUrls) {
                filterChainDefinition.put(authcUrl, "authc");
            }
        }
        bean.setFilterChainDefinitionMap(filterChainDefinition);
        //创建自定义filter
        ShiroLoginFilter filter = new ShiroLoginFilter();
        Map<String, Filter> map = new HashMap<>();
        map.put("authc", filter);
        bean.setFilters(map);

        return bean;
    }


    /**
     * 注册过滤器
     */
    @Bean
    public FilterRegistrationBean<DelegatingFilterProxy> filterRegistrationBeanDelegatingFilterProxy() {
        FilterRegistrationBean<DelegatingFilterProxy> bean = new FilterRegistrationBean<>();
        //创建过滤器
        DelegatingFilterProxy proxy = new DelegatingFilterProxy();
        bean.setFilter(proxy);
        bean.addInitParameter("targetFilterLifecycle", "true");
        bean.addInitParameter("targetBeanName", "shiroFilter");
//        bean.addUrlPatterns();
        List<String> servletNames = new ArrayList<>();
        servletNames.add(DispatcherServletAutoConfiguration.DEFAULT_DISPATCHER_SERVLET_BEAN_NAME);
        bean.setServletNames(servletNames);
        return bean;
    }


    /**
     * 这里是为了能在html页面引用shiro标签，上面两个函数必须添加，不然会报错
     */
    @Bean(name = "shiroDialect")
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }

    /*加入注解的使用，不加入这个注解不生效--开始*/

    /**
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor =
                new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    @Bean
    public DefaultAdvisorAutoProxyCreator getDefaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }
    /*加入注解的使用，不加入这个注解不生效--结束*/
}


```

## 启动项目测试

项目启动后，在浏览器中输入

http://localhost:8080/login/login?username=zhangsan&password=123

会得到返回错误的json

![Snipaste_2020-02-01_12-03-44](https://github.com/Kahen/springboot-shiro2/blob/master/images/Snipaste_2020-02-01_12-03-44.png)

访问查询用户

http://localhost:8080/user/query

![image-20200201123122104]((https://github.com/Kahen/springboot-shiro2/blob/master/images/image-20200201123122104.png)

访问正确的用户

http://localhost:8080/login/login?username=zhangsan&password=123456

![image-20200201123322723]((https://github.com/Kahen/springboot-shiro2/blob/master/images/image-20200201123322723.png)

重新访问http://localhost:8080/user/query

![image-20200201123901961]((https://github.com/Kahen/springboot-shiro2/blob/master/images/image-20200201123901961.png)

![image-20200201124018987]((https://github.com/Kahen/springboot-shiro2/blob/master/images/image-20200201124018987.png)

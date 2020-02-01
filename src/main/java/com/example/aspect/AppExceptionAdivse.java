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


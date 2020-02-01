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

public class ShiroLoginFilter  extends FormAuthenticationFilter {

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        //if (isAjax(request)) {
        httpServletResponse.setCharacterEncoding("UTF-8");
        httpServletResponse.setContentType("application/json");
        Map<String,Object> resultData = new HashMap<>();
        resultData.put("code", -1);
        resultData.put("msg", "未登录!");
        httpServletResponse.getWriter().write(JSONObject.toJSON(resultData).toString());
	/*	} else {
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

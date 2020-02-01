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

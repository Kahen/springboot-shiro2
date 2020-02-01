package com.example.service;


import com.example.domain.User;

public interface UserService {

	/**
	 * 根据用户ID查询用户对象
	 */
	public User queryUserByUserName(String username);
}

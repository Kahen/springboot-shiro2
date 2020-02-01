package com.example.service;

import java.util.List;

public interface PermissionService {

	/**
	 * 根据用户ID查询用户权限列表
	 */
	public List<String> queryPermissionByUserId(Integer userId);
}

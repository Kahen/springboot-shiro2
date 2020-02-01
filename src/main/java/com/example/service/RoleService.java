package com.example.service;

import java.util.List;

public interface RoleService {

	/**
	 * 根据用户名查询用户角色列表
	 */
	public List<String> queryRoleByUserId(Integer userId);
}

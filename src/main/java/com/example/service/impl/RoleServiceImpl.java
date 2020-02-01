package com.example.service.impl;

import com.example.domain.Role;
import com.example.mapper.RoleMapper;
import com.example.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class RoleServiceImpl implements RoleService {
	
	@Autowired
	private RoleMapper roleMapper;

	@Override
	public List<String> queryRoleByUserId(Integer userId) {
		List<Role> list = roleMapper.queryRolesByUserId(userId);
		List<String> roles=new ArrayList<String>();
		for (Role role : list) {
			roles.add(role.getRolename());
		}
		return roles;
	}


}

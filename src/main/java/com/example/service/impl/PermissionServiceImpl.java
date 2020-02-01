package com.example.service.impl;

import com.example.domain.Permission;
import com.example.mapper.PermissionMapper;
import com.example.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class PermissionServiceImpl implements PermissionService {
	
	@Autowired
	private PermissionMapper permissionMapper;

	@Override
	public List<String> queryPermissionByUserId(Integer userId) {
		List<Permission> list = permissionMapper.queryPermissionByUserId(userId);
		List<String> permissions=new ArrayList<>();
		
		for (Permission permission : list) {
			permissions.add(permission.getPercode());
		}
		return permissions;
	}

}

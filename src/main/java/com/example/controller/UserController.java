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

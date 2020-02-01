package com.example.mapper;

import com.example.domain.Role;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface RoleMapper {
    int deleteByPrimaryKey(Integer roleid);

    int insert(Role record);

    int insertSelective(Role record);

    Role selectByPrimaryKey(Integer roleid);

    int updateByPrimaryKeySelective(Role record);

    int updateByPrimaryKey(Role record);
    
    /**
     * 根据用户ID查询角色
     * 1，如果只有一个参数，可以不加   怎么取？#{userId}    #{saddfasdfasd}
     * 2,如果有多个参数 [如何区分]  
     * 			1，注解 @Param("userId")
     *          2, #{param1}   #{param2}      #{1}  @{2}
     */
    List<Role> queryRolesByUserId(@Param("userId") Integer userId);
}
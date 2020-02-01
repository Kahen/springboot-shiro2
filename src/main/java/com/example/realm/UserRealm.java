package com.example.realm;

import com.example.common.ActiverUser;
import com.example.domain.User;
import com.example.service.PermissionService;
import com.example.service.RoleService;
import com.example.service.UserService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class UserRealm extends AuthorizingRealm {

	@Autowired
	private UserService userService;

	@Autowired
	private RoleService roleService;

	@Autowired
	private PermissionService permissionService;

	@Override
	public String getName() {
		return this.getClass().getSimpleName();
	}

	/**
	 * 作认证
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		// 得到用户名
		String username = token.getPrincipal().toString();
		// 根据用户名查询用户对象
		User user = userService.queryUserByUserName(username);
		if (null != user) {
			ActiverUser activerUser = new ActiverUser();
			activerUser.setUser(user);
			// 根据用户名查询角色
			List<String> roles = roleService.queryRoleByUserId(user.getUserid());
			// 根据用户名查询权限
			List<String> permissions = permissionService.queryPermissionByUserId(user.getUserid());
			activerUser.setRoles(roles);
			activerUser.setPermissions(permissions);
			ByteSource credentialsSalt = ByteSource.Util.bytes(user.getUsername() + user.getAddress());
			/**
			 * 参数1传输对象 可以传到doGetAuthorizationInfo 也可以传到subject.getPrincipal() 参数2 加密后的字符串
			 * 参数3 盐 参数4 当前类名
			 */
			SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(activerUser, user.getUserpwd(),
					credentialsSalt, getName());
			return info;
		}

		return null;
	}

	/**
	 * 作授权
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		ActiverUser activerUser = (ActiverUser) principals.getPrimaryPrincipal();
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 根据用户名查询角色
		List<String> roles = activerUser.getRoles();
		// 根据用户名查询权限
		List<String> permissions = activerUser.getPermissions();
		if (null != roles && roles.size() > 0) {
			info.addRoles(roles);
		}
		if (null != permissions && permissions.size() > 0) {
			info.addStringPermissions(permissions);
		}
		return info;// 如果返回空，代表当前主体没有任何角色和权限信息
	}

}

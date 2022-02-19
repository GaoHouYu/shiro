package realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.SimpleByteSource;

public class Md5Realm extends AuthorizingRealm {

    /**
     * 用户认证
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        //这里假设从数据库查出来的账号密码
        String userName = "dm";
        System.out.println("输入的MD5账号为"+userName);
        String passWord = "8f1f0d7abf1b104f866585eb4c801657";
        //第二个参数为盐值，第三个参数为加密次数
/*        Md5Hash md5Hash = new Md5Hash(passWord,"abc",1024);
        System.out.println(String.valueOf(md5Hash));*/
        //这个账号对应的盐值
        String salt = "abc";
        if (!token.getUsername().equals(userName)) {
            //表示账号不存在
            return null;
        }
        return new SimpleAuthenticationInfo(userName,passWord,new SimpleByteSource(salt),"MyRealm");
    }

    /**
     * 用户授权
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }
}

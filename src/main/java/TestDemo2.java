import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;


public class TestDemo2 {


    public static void main(String[] args) {
        //获取一个SecurityManager工厂对象，加载shiro配置文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro_customer.ini");
        //通过factory获取secutityManager对象
        SecurityManager securityManager = factory.getInstance();
        //将securityManager添加到运行时环境中
        SecurityUtils.setSecurityManager(securityManager);
        //通过SecurityManager获取Subject对象
        Subject subject = SecurityUtils.getSubject();
        //前端传入的用户密码
        String loginName = "dm";
        String passWord = "0616";
        //第二个参数为盐值，第三个参数为加密次数
        Md5Hash md5Hash = new Md5Hash(passWord,"abc");
        System.out.println(md5Hash);
        //将用户密码封装成一个token
        AuthenticationToken token = new UsernamePasswordToken(loginName, String.valueOf(md5Hash));
        try {
            subject.login(token);
            System.out.println("成功登录！！");
        } catch (UnknownAccountException e) {
            System.out.println("账号不存在！");
        } catch (IncorrectCredentialsException e) {
            System.out.println("账号密码不匹配");
        }
    }
}

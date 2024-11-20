package vn.dodientu.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import vn.dodientu.dto.LoginRequest;
import vn.dodientu.model.Role;
import vn.dodientu.model.User;
import vn.dodientu.repository.RoleRepository;
import vn.dodientu.repository.UserRepository;
import vn.dodientu.service.interfaces.IAuthService;
import vn.dodientu.service.interfaces.IEmailService;
import vn.dodientu.service.interfaces.IRedisService;
import vn.dodientu.service.interfaces.IUserService;

@Controller
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private IUserService userService;

    @Autowired
    private IAuthService authService;
    
    @Autowired
    private IRedisService redisService;
    
    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private UserRepository userRepository;

    // Trang đăng nhập
    @GetMapping("/login")
    public String loginPage() {
        return "login"; // Chuyển tới login.jsp
    }

    // Xử lý yêu cầu đăng nhập
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, Model model) {
        try {
            LoginRequest loginRequest = new LoginRequest(username, password);
            authService.login(loginRequest); // Giả sử method login() trong IAuthService xử lý đăng nhập
            return "home"; // Đăng nhập thành công, chuyển đến trang chủ hoặc trang bạn muốn
        } catch (BadCredentialsException e) {
            model.addAttribute("error", "Invalid username or password");
            return "login"; // Quay lại trang login nếu đăng nhập thất bại
        }
	    }
	
	    @GetMapping("/register")
	    public String registerPage() {
	        return "register";
	    }

    // Phương thức đăng ký
    @PostMapping("/register")
    public String registerUser(@RequestParam String username,
                               @RequestParam String email,
                               @RequestParam String password,
                               @RequestParam String confirmPassword,
                               @RequestParam String role,  // Vai trò người dùng
                               Model model) {

        // Kiểm tra nếu mật khẩu và xác nhận mật khẩu không khớp
        if (!password.equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match!");
            return "register";  // Trả về lại trang đăng ký nếu mật khẩu không khớp
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(password);
        user.setRole(role, roleRepository);  // Gán vai trò người dùng chọn

        // Đăng ký người dùng và xử lý OTP trong service
        userService.registerUser(user);

        // Chuyển hướng đến trang nhập OTP
        model.addAttribute("email", email);
        return "confirm-email"; // Trang để người dùng nhập OTP
    }
    
    @GetMapping("/confirm-email")
    public String confirmEmailPage() {
        return "confirm-email";
    }


    @PostMapping("/confirm-email")
    public String verifyOtp(@RequestParam String email,
                            @RequestParam String otp,
                            Model model) {

        // Lấy OTP từ Redis
        String cachedOtp = redisService.getOtp(email);

        // Kiểm tra OTP hợp lệ
        if (cachedOtp == null) {
            model.addAttribute("error", "OTP has expired or does not exist.");
            return "confirm-email"; // OTP đã hết hạn hoặc không tồn tại
        }

        if (!cachedOtp.equals(otp)) {
            model.addAttribute("error", "Invalid OTP.");
            return "confirm-email"; // OTP không đúng
        }

        // Xác thực thành công, xóa OTP khỏi Redis
        redisService.deleteOtp(email);

        // Cập nhật trạng thái người dùng (nếu cần)
        User user = userRepository.findByEmail(email).orElse(null);
        if (user != null) {
            user.setIsVerified(true); // Đánh dấu là đã xác thực
            userService.update(user);
        }

        model.addAttribute("message", "Your email has been verified successfully.");
        return "login"; // Chuyển hướng đến trang đăng nhập
    }

    
    @GetMapping("/forgot-password")
    public String forgotpasswordPage() {
        return "forgot-password"; // Chuyển tới register.jsp
    }
    
    // Xử lý yêu cầu đặt lại mật khẩu
    @PostMapping("/forgot-password")
    public String sendForgotPasswordRequest(@RequestParam String email, Model model) {
        try {
            authService.requestPasswordReset(email);
            model.addAttribute("message", "Password reset email has been sent.");
            return "login"; // Quay lại trang login sau khi gửi email đặt lại mật khẩu
        } catch (Exception e) {
            model.addAttribute("error", "Failed to send password reset email: " + e.getMessage());
            return "login"; // Quay lại trang login nếu có lỗi
        }
    }

    // Xử lý đặt lại mật khẩu
    @PostMapping("/reset-password")
    public String resetPassword(@RequestParam String email,
                                 @RequestParam String resetCode,
                                 @RequestParam String password, Model model) {
        try {
            authService.resetPassword(email, resetCode, password);
            model.addAttribute("message", "Your password has been reset successfully.");
            return "login"; // Quay lại trang login sau khi đặt lại mật khẩu thành công
        } catch (Exception e) {
            model.addAttribute("error", "Failed to reset password: " + e.getMessage());
            return "login"; // Quay lại trang login nếu có lỗi
        }
    }
}

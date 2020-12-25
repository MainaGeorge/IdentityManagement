using IdentityManagement.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity.UI.V4.Pages.Account.Internal;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace IdentityManagement.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;

        public AccountController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = new AppUser()
            {
                UserName = model.Name,
                Email = model.Email,
                Name = model.Name
            };

            var registerUser = await _userManager.CreateAsync(user, model.Password);
            if (registerUser.Succeeded)
            {
                await _emailSender.SendEmailAsync(model.Email, "Welcome", "<h1> Welcome to our app </h2>");
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction(nameof(Index), controllerName: "Home");
            }

            AddModelStateErrors(registerUser);
            return View(model);


        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            var returnUrl = TempData["ReturnUrl"] ?? Url.Content("~/");
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);

            var signIn = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, false);

            if (signIn.Succeeded)
                return RedirectToAction(nameof(Index), controllerName: "Home");

            ModelState.AddModelError(string.Empty, "invalid password email combination");

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction(nameof(Index), "Home");
        }
        public IActionResult ForgotPassword()
        {
            return View(nameof(ResetPassword));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ResetPassword model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return View(nameof(ForgotPasswordConfirmation));

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

            var callbackUrl = Url.Action(nameof(ChangePassword), "Account",
                new { userId = user.Id, resetToken }, protocol: HttpContext.Request.Scheme);
            const string subject = "Reset your password";
            var link = $"<a style=\" color: red; \" href={callbackUrl}>Reset password here </a>";

            await _emailSender.SendEmailAsync(model.Email, subject, Message(link));

            return View(nameof(ForgotPasswordConfirmation));
        }

        [HttpGet]
        public IActionResult ChangePassword(string userId = null, string resetToken = null)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(resetToken))
                return View("Error");

            var model = new ChangePasswordModel() { UserId = userId, ResetToken = resetToken };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user == null)
                ModelState.AddModelError(string.Empty, "Something went wrong with the reset process");
            else
            {
                var resetPassword = await _userManager.ResetPasswordAsync(user, model.ResetToken, model.Password);
                if (!resetPassword.Succeeded)
                    AddModelStateErrors(resetPassword);
            }

            return RedirectToAction(nameof(Login), "Account");
        }

        private static string Message(string link)
        {
            var textMessage = @"You are receiving this message because you requested to change or update your email
                password. If you did not make this request please contact the administration as soon as possible. Click on the link provided below to 
                change your password." + Environment.NewLine + link;

            return textMessage;
        }

        private void AddModelStateErrors(IdentityResult result)
        {
            foreach (var identityError in result.Errors)
            {
                ModelState.AddModelError(identityError.Code, identityError.Description);
            }
        }
    }
}

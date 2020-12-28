using IdentityManagement.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity.UI.V4.Pages.Account.Internal;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Claims;
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
                await SendEmailConfirmationToken(user);
                return RedirectToAction(nameof(Login));
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
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (!user.EmailConfirmed)
            {
                ModelState.AddModelError("", "you must confirm your account using the link sent to you by email");
                return View(model);
            }


            var signIn = await _signInManager.PasswordSignInAsync(user, model.Password,
                model.RememberMe, false);

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
                new { email = user.Email, resetToken }, protocol: HttpContext.Request.Scheme);
            const string subject = "Reset your password";
            var link = $"<a style=\" color: red; \" href={callbackUrl}>Reset password here </a>";

            await _emailSender.SendEmailAsync(model.Email, subject, GenerateMessage("resetPassword", link));

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
            {
                ModelState.AddModelError(string.Empty, "Something went wrong with the reset process");
                return View(model);
            }

            var resetPassword = await _userManager.ResetPasswordAsync(user, model.ResetToken, model.Password);
            if (resetPassword.Succeeded) return RedirectToAction(nameof(Login), "Account");

            AddModelStateErrors(resetPassword);
            return View(model);

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account");
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            return Challenge(properties, provider);
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string remoteError = null)
        {
            if (!string.IsNullOrWhiteSpace(remoteError))
            {
                ModelState.AddModelError(string.Empty, remoteError);
                return View(nameof(Login));
            }

            var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();

            if (externalLoginInfo == null) return RedirectToAction(nameof(Login), "Account");

            var signInUserWithLogin = await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider,
                externalLoginInfo.ProviderKey, false);


            if (!signInUserWithLogin.Succeeded)
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmation()
                {
                    Email = externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Email),
                    Name = externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Name),
                    ExternalProviderDisplayName = externalLoginInfo.ProviderDisplayName
                });

            await _signInManager.UpdateExternalAuthenticationTokensAsync(externalLoginInfo);
            return RedirectToAction(nameof(Index), "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmation model)
        {
            if (!ModelState.IsValid) return View(model);

            var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();

            if (externalLoginInfo == null) return View("Error");

            var applicationUser = new AppUser()
            {
                Email = model.Email,
                Name = model.Name,
                UserName = model.Email
            };

            var createdUser = await _userManager.CreateAsync(applicationUser);

            if (createdUser.Succeeded)
            {
                var addExternalLoginToCreatedUser = await _userManager
                    .AddLoginAsync(applicationUser, externalLoginInfo);

                if (addExternalLoginToCreatedUser.Succeeded)
                {
                    await _signInManager.SignInAsync(applicationUser, false);
                    await _signInManager.UpdateExternalAuthenticationTokensAsync(externalLoginInfo);
                    return RedirectToAction(nameof(Index), "Home");
                }

            }

            AddModelStateErrors(createdUser);

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string email, string token)

        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
                return View("Error");

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null) return View("Error");

            var confirmEmail = await _userManager.ConfirmEmailAsync(user, token);

            if (!confirmEmail.Succeeded) return View("Error");

            await _signInManager.SignInAsync(user, false);
            return RedirectToAction(nameof(Index), "Home");

        }
        private static string GenerateMessage(string typeOfMessage, string link)
        {
            return typeOfMessage switch
            {
                "resetPassword" => @"You are receiving this message because you requested to change or update your email
                            password. If you did not make this request please contact the administration as soon as possible. Click on the link provided below to 
                            change your password." + Environment.NewLine + link,

                "register" => @"You are receiving this message because you signed up for an account with us.
                             Click on the link provided below to confirm and activate your account " +
                                   Environment.NewLine + link,

                _ => throw new Exception()
            };
        }

        private void AddModelStateErrors(IdentityResult result)
        {
            foreach (var identityError in result.Errors)
            {
                ModelState.AddModelError(identityError.Code, identityError.Description);
            }
        }

        private async Task SendEmailConfirmationToken(IdentityUser user)
        {
            var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.Action("ConfirmEmail", "Account",

                new { email = user.Email, token = emailConfirmationToken },
                HttpContext.Request.Scheme);
            var confirmLink = $"<a style=\" color: red; \" href={callbackUrl}>Confirm your account</a>";

            var message = GenerateMessage("register", confirmLink);

            const string subject = "Account confirmation";

            await _emailSender.SendEmailAsync(user.Email, subject, message);

        }



    }
}

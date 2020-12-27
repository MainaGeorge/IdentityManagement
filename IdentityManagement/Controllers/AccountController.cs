﻿using IdentityManagement.Models;
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

            var signInUserWithLogin = await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider
                , externalLoginInfo.ProviderKey, false);


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
                var addLoginAsyncToCreatedUser = await _userManager.AddLoginAsync(applicationUser, externalLoginInfo);
                if (addLoginAsyncToCreatedUser.Succeeded)
                {
                    await _signInManager.SignInAsync(applicationUser, false);
                    await _signInManager.UpdateExternalAuthenticationTokensAsync(externalLoginInfo);
                    return RedirectToAction(nameof(Index), "Home");
                }

            }

            AddModelStateErrors(createdUser);

            return View(model);
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

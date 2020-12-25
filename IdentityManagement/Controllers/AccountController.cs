using IdentityManagement.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;

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
        public IActionResult Login(string returnUrl = null)
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
        public async Task<IActionResult> ForgotPassword()
        {
            return RedirectToAction("Index", controllerName: "Home");
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

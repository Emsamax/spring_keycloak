package org.springframework.samples.petclinic.account;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AccountController {
	@GetMapping("/account")
	public String showAccount(Model model, @AuthenticationPrincipal OidcUser user) {
		model.addAttribute("userInfo", user);
		return "accounts/accountDetails";
	}

}

package com.lakkam.springsecurityjdbc;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

	@RequestMapping("/user")
	public String welcomeUser() {
		return "Welcome Nani";
	}
	
	@RequestMapping("/admin")
	public String welcomeAdmin() {
		return "Welcome Lakkam";
	}
	
	@RequestMapping("/exclusiveUser")
	public String welcomeExclusiveUser() {
		return "Welcome Exclusive User Prachu";
	}

}

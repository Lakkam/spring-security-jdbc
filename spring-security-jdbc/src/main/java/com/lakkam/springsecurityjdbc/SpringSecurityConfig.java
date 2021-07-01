package com.lakkam.springsecurityjdbc;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

	//To tell Spring where the data base is configured, we need to have data source object.
	@Autowired
	DataSource dataSource;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		/*
		 * When we add H2 data base as dependency in Spring application, Spring security application be default consideres that as default database
		 * And we dont need to configure seperate DB. So, the moment we autowire datasource object, it considers H2 database.
		 * And we are explicitly saying to spring to use default schema from H2 DB.
		 * Intern, this Authentication uses UserDetailsService, so if we use User object and add users and roles to that, by default
		 * it creates users and authorization tables and insert the values that we pass to these User objects. UserDetailsServices does this magic.
		 * AuthenticationProvider calls this UserDetailsService
		 */
		
		auth.jdbcAuthentication().dataSource(dataSource).withDefaultSchema().
									withUser(User.withUsername("lakkam").password("lakkam").roles("ADMIN"))
									.withUser(User.withUsername("nani").password("nani").roles("USER"))
									.withUser(User.withUsername("prachu").password("prachu").roles("EUSER"));
	}

	/*
	 * This method is for configuring the authorization roles.
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/admin").hasRole("ADMIN").antMatchers("/user").hasAnyRole("ADMIN", "USER")
				.antMatchers("/exclusiveUser").hasRole("EUSER").and().formLogin();
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

}

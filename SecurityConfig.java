package com.dayo.security.springsecurityldap.config;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.encoding.LdapShaPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	//Logging Functionality
	private static final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);

	
	// Retrieves these value from the application.properties 
		@Value("${AD_DOMAIN}")
		private String adDomain;

		@Value("${AD_URL}")
		private String adUrl;

		@Value("${AD_GROUP}")
		private String adGroup;
		
		@Value("${AD_USER_SEARCH_BASE}")
		private String adUserSearchBase;

		@Value("${AD_USER_DN_PATTERNS}")
		private String adUserDnPatterns;

		@Value("${AD_GROUP_SEARCH_BASE}")
		private String adGroupSearchBase;
		
		@Value("${ldap.urls}")
		private String ldapUrls;
		
		@Value("${ldap.base.dn}")
		private String ldapBaseDn;
		
		@Value("${ldap.username}")
		private String ldapSecurityPrincipal;
		
		@Value("${ldap.password}")
		private String ldapPrincipalPassword;
		
		@Value("${ldap.user.dn.pattern}")
		private String ldapUserDnPattern;
		
		@Value("${ldap.enabled}")
		private String ldapEnabled;

	@Autowired
	private DefaultSpringSecurityContextSource context;
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.anyRequest().fullyAuthenticated()
				.and()
			.formLogin();
	}
	
	@PostConstruct
    public void setup(){
		log.info("~~~Authentication Source settings " + context.getAuthenticationSource());
    }
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
		.ldapAuthentication()
		.userSearchFilter("(sAMAccountName={0})")
        .contextSource(context);
			
			
}
	@Bean
	public DefaultSpringSecurityContextSource createContext() {
		DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource("SERVER_LINK");
	    contextSource.setUserDn(ldapSecurityPrincipal);
	    contextSource.setPassword(ldapPrincipalPassword);
	    contextSource.setReferral("follow");
	    Map<String, Object> environment = new HashMap<>();
	    environment.put("com.sun.jndi.ldap.connect.timeout", "10000");
	    environment.put("com.sun.jndi.ldap.read.timeout", "15000");
	    environment.put("com.sun.jndi.ldap.connect.pool.initsize","6");
	    environment.put("com.sun.jndi.ldap.connect.pool.maxsize","6");
	    contextSource.setBaseEnvironmentProperties(environment);
	    return contextSource;
}
}	

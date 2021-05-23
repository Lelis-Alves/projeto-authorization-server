package com.ealves.authorization.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

/**
 * - Configurando o fluxo Authorization Server com Password Credentials e Opaque Tokens
 * Classe Adaptador para customizar o Authorization Server
 * Configurar o Password Credentials.
 * Cliente se identificar.pode ser mobile ou web
 * - Para um client solicitar um acces-token a um autorizatio server, 
 * ele se autenticar ele precisa informar o client id, usuario e senha.
 * @author Elias Alves
 *
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory() // - Para um client solicitar um acces-token a um autorizationserver, ele se autenticar ele precisa informar o 
				.withClient("ealvesfood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password")
				.scopes("write", "read")
				.accessTokenValiditySeconds(60 * 60 * 6) // 6 horas (padrão é 12 horas)
		.and()
		.withClient("checktoken")
			.secret(passwordEncoder.encode("check123"));
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
		security.checkTokenAccess("permitAll()");
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager);
	}
	
}
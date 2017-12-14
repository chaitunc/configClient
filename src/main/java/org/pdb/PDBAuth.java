package org.pdb;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.oauth2.client.token.JdbcClientTokenServices;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CompositeFilter;
import org.springframework.web.filter.CorsFilter;

import com.zaxxer.hikari.HikariDataSource;

@SpringBootApplication
@EnableAutoConfiguration
@EnableOAuth2Client
@EnableWebSecurity
@EnableDiscoveryClient
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class PDBAuth extends WebSecurityConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(PDBAuth.class, args);

	}

	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	@Bean
	public ClientTokenServices clientTokenServices() {
		return new JdbcClientTokenServices(datasource());
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	@ConfigurationProperties("spring.datasource")
	public HikariDataSource datasource() {
		return (HikariDataSource) DataSourceBuilder.create().type(HikariDataSource.class).build();
	}

	// This method is used for override HttpSecurity of the web Application.
	// We can specify our authorization criteria inside this method.
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// @formatter:off
		http.csrf().disable()
			.antMatcher("/**").authorizeRequests()
			.antMatchers( "/index.html","/login**","/favicon.ico","/refresh").permitAll()
			.anyRequest().authenticated()
			.and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/index.html"))
			.and().cors().disable()
			.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
			
		// @formatter:on
	}

	private Filter ssoFilter() {

		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<>();

		filters.add(ssoFilter(google(), "/login/google"));
		filters.add(ssoFilter(github(), "/login/github"));

		filter.setFilters(filters);
		return filter;
	}

	private Filter ssoFilter(ClientResources client, String path) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		AccessTokenProviderChain accessTokenProvider = new AccessTokenProviderChain(Arrays.<AccessTokenProvider>asList(
				new AuthorizationCodeAccessTokenProvider(), new ImplicitAccessTokenProvider(),
				new ResourceOwnerPasswordAccessTokenProvider(), new ClientCredentialsAccessTokenProvider()));
		accessTokenProvider.setClientTokenServices(clientTokenServices());
		template.setAccessTokenProvider(accessTokenProvider);
		filter.setRestTemplate(template);
		CustomUserInfoTokenServices tokenServices = new CustomUserInfoTokenServices(
				client.getResource().getUserInfoUri(), client.getClient().getClientId(), clientTokenServices(),
				client.getResource().getId());
		tokenServices.setRestTemplate(template);
		filter.setTokenServices(tokenServices);
		return filter;
	}

	@Bean
	@ConfigurationProperties("github")
	public ClientResources github() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("google")
	public ClientResources google() {
		return new ClientResources();
	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	class ClientResources {

		@NestedConfigurationProperty
		private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

		@NestedConfigurationProperty
		private ResourceServerProperties resource = new ResourceServerProperties();

		public AuthorizationCodeResourceDetails getClient() {
			return client;
		}

		public ResourceServerProperties getResource() {
			return resource;
		}
	}

	@Configuration
	@EnableAuthorizationServer
	protected class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

		private static final String PDB_GOOGLE_SECRET = "pdb.auth.client.google.secret";

		private static final String PDB_GITHUB_SECRET = "pdb.auth.client.github.secret";

		private static final String PDB_GATEWAY_SECRET = "pdb.auth.client.gateway.secret";

		@Autowired
		@Qualifier("authenticationManagerBean")
		private AuthenticationManager authenticationManager;

		@Bean
		public TokenStore tokenStore() {
			return new JwtTokenStore(accessTokenConverter());
		}

		@Bean
		public JwtAccessTokenConverter accessTokenConverter() {
			JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
			converter.setSigningKey("123");
			return converter;
		}

		@Bean
		@Primary
		public DefaultTokenServices tokenServices() {
			DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
			defaultTokenServices.setTokenStore(tokenStore());
			defaultTokenServices.setSupportRefreshToken(true);
			defaultTokenServices.setTokenEnhancer(accessTokenConverter());
			return defaultTokenServices;
		}

		@Autowired
		Environment env;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

			// @formatter:off
			clients.inMemory()
				.withClient("PDB-GOOGLE")
					.authorizedGrantTypes("client_credentials", "authorization_code")
					.authorities("ROLE_GOOGLE")
					.scopes("read", "write")
					.secret(env.getRequiredProperty(PDB_GOOGLE_SECRET))
				.and()
				.withClient("PDB-GITHUB")
					.authorizedGrantTypes("client_credentials", "authorization_code")
					.authorities("ROLE_GITHUB")
					.scopes("read", "write")
					.secret(env.getRequiredProperty(PDB_GITHUB_SECRET))
				.and()
				.withClient("PDB-GATEWAY")
					.authorizedGrantTypes("client_credentials", "authorization_code")
					.authorities("ROLE-GATEWAY")
					.scopes("read", "write")
					.secret(env.getRequiredProperty(PDB_GATEWAY_SECRET));
					//.redirectUris("http://localhost:9998/pdb-gateway/login");

			// @formatter:on
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.authenticationManager(authenticationManager).tokenStore(tokenStore());
		}

	}

	@EnableResourceServer
	static class PDBResourceServer extends ResourceServerConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
		}

	}

	@Bean
	public RequestContextListener requestContextListener() {
		return new RequestContextListener();
	}

	@Bean
	public TokenStore tokenStore() {
		return new InMemoryTokenStore();
	}

	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
		config.addAllowedOrigin("*");
		config.addAllowedHeader("*");
		config.addAllowedMethod("*");
		source.registerCorsConfiguration("/**", config);

		return new CorsFilter(source);
	}

}

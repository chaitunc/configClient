package org.pdb;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class HomeController {

	@Autowired
	private DiscoveryClient discoveryClient;

	@RequestMapping("/")
	public ModelAndView home() {

		return new ModelAndView("redirect:http://" + serviceUrl() + "/home");

	}

	public String serviceUrl() {
		List<ServiceInstance> list = discoveryClient.getInstances("pdb-gateway");
		if (list != null && list.size() > 0) {
			return list.get(0).getUri().toString();
		}
		return null;
	}

	@RequestMapping({ "/user", "/me" })
	public Map<String, Object> user(Principal principal) {
		OAuth2Authentication auth = (OAuth2Authentication) principal;
		Map<String, Object> user = new HashMap<String, Object>();
		if (principal != null) {
			OAuth2Authentication userAuthentication = (OAuth2Authentication) auth.getUserAuthentication();
			Serializable resourceId = userAuthentication.getOAuth2Request().getExtensions().get("resourceId");
			user.put("userName", principal.getName());
			user.put("AUTHENTICATED_BY", resourceId);
		}
		return user;
	}
}

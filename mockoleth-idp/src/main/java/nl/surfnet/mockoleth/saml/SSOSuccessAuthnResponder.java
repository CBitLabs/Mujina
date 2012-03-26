/*
*   Copyright 2012 SURFnet.nl
*
*   Licensed under the Apache License, Version 2.0 (the "License");
*   you may not use this file except in compliance with the License.
*   You may obtain a copy of the License at
*
*       http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*   See the License for the specific language governing permissions and
*   limitations under the License.
*/

package nl.surfnet.mockoleth.saml;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nl.surfnet.mockoleth.saml.xml.AuthnResponseGenerator;
import nl.surfnet.mockoleth.saml.xml.EndpointGenerator;
import nl.surfnet.mockoleth.spring.AuthnRequestInfo;
import nl.surfnet.mockoleth.util.IDService;
import nl.surfnet.mockoleth.util.TimeService;
import nl.surfnet.mockoleth.model.Configuration;

import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.HttpRequestHandler;

public class SSOSuccessAuthnResponder implements HttpRequestHandler, InitializingBean {

	private final String issuingEntityName; 
	private final TimeService timeService;
	private final IDService idService;
	private int responseValidityTimeInSeconds;
	private final BindingAdapter adapter;
	private CredentialResolver credentialResolver;
	Credential signingCredential;
	EndpointGenerator endpointGenerator;
	AuthnResponseGenerator authnResponseGenerator;

    @Autowired
    Configuration configuration;
	
	private final static Logger logger = LoggerFactory
			.getLogger(SSOSuccessAuthnResponder.class);
	
	
	public SSOSuccessAuthnResponder(String issuingEntityName, TimeService timeService,
			IDService idService,
			BindingAdapter adapter, CredentialResolver credentialResolver) {
		super();
		this.issuingEntityName = issuingEntityName;
		this.timeService = timeService;
		this.idService = idService;
		this.adapter = adapter;
		this.credentialResolver = credentialResolver;
	}


	@Required
	public void setResponseValidityTimeInSeconds(int responseValidityTimeInSeconds) {
		this.responseValidityTimeInSeconds = responseValidityTimeInSeconds;
	}
	
	


	@Override
	public void afterPropertiesSet() throws Exception {

        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(issuingEntityName));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        signingCredential = credentialResolver.resolveSingle(criteriaSet);
        Validate.notNull(signingCredential);

		authnResponseGenerator = new AuthnResponseGenerator(signingCredential, issuingEntityName, timeService, idService, configuration);
		endpointGenerator = new EndpointGenerator();

	}


	@Override
	public void handleRequest(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		AuthnRequestInfo info = (AuthnRequestInfo) request.getSession().getAttribute(AuthnRequestInfo.class.getName());
		
		if(info == null) {
			logger.warn("Could not find AuthnRequest on the request.  Responding with SC_FORBIDDEN.");
			response.sendError(HttpServletResponse.SC_FORBIDDEN);
			return;
		}
		
		logger.debug("AuthnRequestInfo: {}", info);
		
		UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
		DateTime authnInstant = new DateTime(request.getSession().getCreationTime());
		
		Response authResponse = authnResponseGenerator.generateAuthnResponse(authToken, info.getAssertionConumerURL(), responseValidityTimeInSeconds, info.getAuthnRequestID(),authnInstant);
		Endpoint endpoint = endpointGenerator.generateEndpoint(org.opensaml.saml2.metadata.AssertionConsumerService.DEFAULT_ELEMENT_NAME, info.getAssertionConumerURL(), null);
		
		request.getSession().removeAttribute(AuthnRequestInfo.class.getName());
		
		//we could use a different adapter to send the response based on request issuer...
		try {
			adapter.sendSAMLMessage(authResponse, endpoint, signingCredential, response);
		} catch (MessageEncodingException mee) {
			logger.error("Exception encoding SAML message", mee);
			response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
		}
	}
}
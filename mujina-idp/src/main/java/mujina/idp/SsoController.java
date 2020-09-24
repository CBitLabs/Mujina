package mujina.idp;

import mujina.api.IdpConfiguration;
import mujina.saml.SAMLAttribute;
import mujina.saml.SAMLPrincipal;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

@Controller
public class SsoController {

  @Autowired
  private SAMLMessageHandler samlMessageHandler;

  @Autowired
  private SAMLMessageHandler samlMessageHandlerWithoutSigning;

  @Autowired
  private IdpConfiguration idpConfiguration;

  @GetMapping("/SingleSignOnServiceIdp")
  public void singleSignOnServiceIdpGet(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
    throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException {
    doSSOIdp(request, response, authentication, false);
  }

  @GetMapping("/SingleSignOnService")
  public void singleSignOnServiceGet(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
    throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException {
    doSSO(request, response, authentication, false);
  }

  @PostMapping("/SingleSignOnService")
  public void singleSignOnServicePost(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
    throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException {
    doSSO(request, response, authentication, true);
  }

  private void doSSO(HttpServletRequest request, HttpServletResponse response, Authentication authentication, boolean postRequest) throws ValidationException, SecurityException, MessageDecodingException, MarshallingException, SignatureException, MessageEncodingException, MetadataProviderException {
    SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, postRequest);
    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

    String assertionConsumerServiceURL = idpConfiguration.getAcsEndpoint() != null ? idpConfiguration.getAcsEndpoint() : authnRequest.getAssertionConsumerServiceURL();

    String name = authentication.getName();

    String nameidType = NameIDType.UNSPECIFIED;

    if (name.contains("@")) {
      nameidType = NameIDType.EMAIL;
    }

    if (name.contains("==")) {
      String[] components = name.split("==", 2);
      nameidType = components[0];
      name = components[1];
    }

    SAMLPrincipal principal = new SAMLPrincipal(
      name,
      nameidType,
      attributes(authentication.getName()),
      authnRequest.getIssuer().getValue(),
      authnRequest.getID(),
      assertionConsumerServiceURL,
      messageContext.getRelayState());

    if (idpConfiguration.isSignMessage()) {
      samlMessageHandler.sendAuthnResponse(principal, response, idpConfiguration.isSignAssertion());
    } else {
      samlMessageHandlerWithoutSigning.sendAuthnResponse(principal, response, idpConfiguration.isSignAssertion());
    }
  }

  private void doSSOIdp(HttpServletRequest request, HttpServletResponse response, Authentication authentication, boolean postRequest) throws ValidationException, SecurityException, MessageDecodingException, MarshallingException, SignatureException, MessageEncodingException, MetadataProviderException {

    String assertionConsumerServiceURL = idpConfiguration.getAcsEndpoint();

    String name = authentication.getName();

    String nameidType = NameIDType.UNSPECIFIED;

    if (name.contains("@")) {
      nameidType = NameIDType.EMAIL;
    }

    if (name.contains("==")) {
      String[] components = name.split("==", 2);
      nameidType = components[0];
      name = components[1];
    }

    SAMLPrincipal principal = new SAMLPrincipal(
      name,
      nameidType,
      attributes(authentication.getName()),
      idpConfiguration.getSpEntityId(),
      null,
      assertionConsumerServiceURL,
      request.getParameter("relaystate"));

    if (idpConfiguration.isSignMessage()) {
      samlMessageHandler.sendAuthnResponse(principal, response, idpConfiguration.isSignAssertion());
    } else {
      samlMessageHandlerWithoutSigning.sendAuthnResponse(principal, response, idpConfiguration.isSignAssertion());
    }
  }

  private List<SAMLAttribute> attributes(String uid) {
    Map<String, List<String>> result = new HashMap<>();
    result.putAll(idpConfiguration.getAttributes());

    Optional<Map<String, List<String>>> optionalMap = idpConfiguration.getUsers().stream().filter(user -> user
      .getPrincipal()
      .equals(uid)).findAny().map(user -> user.getAttributes());
    optionalMap.ifPresent(map -> result.putAll(map));
    return result.entrySet().stream()
      .map(entry ->  entry.getKey().equals("urn:mace:dir:attribute-def:uid") ?
        new SAMLAttribute(entry.getKey(), singletonList(uid)) :
        new SAMLAttribute(entry.getKey(), entry.getValue()))
      .collect(toList());
  }

}

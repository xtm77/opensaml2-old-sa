package com.example.opensaml26xsajava8.controller;

import com.example.opensaml26xsajava8.saml.SAMLUtility;
import lombok.RequiredArgsConstructor;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@RequiredArgsConstructor
@Controller
@RequestMapping(path = {"", "/"})
public class DefaultController {

    private final SAMLUtility samlUtility;

    @GetMapping(path = {"", "/index"})
    public ModelAndView index() {
        ModelAndView mv = new ModelAndView();
        mv.addObject("controllerName", this.getClass().getCanonicalName());
        mv.setViewName("/index");
        return mv;
    }

    @PostMapping("/saml/sso")
    public String samlSSO(HttpServletRequest request, HttpSession session) {
        SAMLMessageContext messageContext;
        Response samlResponse;
        Assertion assertion;
        String nameID = "";

        try {
            messageContext = samlUtility.extractSAMLMessageContext(request);
            samlResponse = (Response) messageContext.getInboundSAMLMessage();
            samlUtility.validateSignature(samlResponse);
            samlUtility.checkAuthnInstant(samlResponse);
            assertion = samlResponse.getAssertions().get(0);
            nameID = assertion.getSubject().getNameID().getValue();
            session.setAttribute("nameID", nameID);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "sso";
    }

}

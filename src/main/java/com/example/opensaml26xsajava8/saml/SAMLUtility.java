package com.example.opensaml26xsajava8.saml;

import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

@Slf4j
@Component
public class SAMLUtility {

    public SAMLUtility() {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
    }

    public SAMLMessageContext extractSAMLMessageContext(HttpServletRequest request)
            throws MessageDecodingException, SecurityException {
        BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
        messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        HTTPPostDecoder decoder = new HTTPPostDecoder();
        decoder.decode(messageContext);
        return messageContext;
    }

    public void validateSignature(Response samlResponse) throws Exception {
        try {
            Signature signature = samlResponse.getSignature();
            PublicKey publicKey = extractPublicKey(signature);
            SignatureValidator validator = createValidator(publicKey);
            validator.validate(samlResponse.getSignature());
            log.info("Signature validation success");
        } catch (CertificateException e) {
            log.error("Invalid certification(public key)", e);
            throw new Exception("Invalid certification(public key)", e);
        } catch (ValidationException e) {
            log.error("Signature validation fail.", e);
            throw new Exception("Signature validation fail", e);
        }
    }

    private PublicKey extractPublicKey(Signature signature) throws CertificateException {
        X509Data x509Data = signature.getKeyInfo().getX509Datas().get(0);
        X509Certificate cert = x509Data.getX509Certificates().get(0);
        String wrappedCert = wrapBase64String(cert.getValue());
        //log.info(wrappedCert);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(wrappedCert.getBytes()));
        return certificate.getPublicKey();
    }

    private String wrapBase64String(String base64String) {
        int lineLength = 64;
        char[] rawArr = base64String.toCharArray();
        int wrappedArrLength = rawArr.length + (int)Math.ceil(rawArr.length / 64d) - 1;
        char[] wrappedArr = new char[wrappedArrLength];

        int destPosition = 0;
        for (int i = 0; i < rawArr.length; i += lineLength) {
            if (rawArr.length - i > lineLength) {
                System.arraycopy(rawArr, i, wrappedArr, destPosition, lineLength);
                destPosition += lineLength;
                wrappedArr[destPosition] = '\n';
                destPosition += 1;
            } else {
                System.arraycopy(rawArr, i, wrappedArr, destPosition, rawArr.length - i);
            }
        }
        return "-----BEGIN CERTIFICATE-----\n" + String.valueOf(wrappedArr) + "\n-----END CERTIFICATE-----";
    }

    private SignatureValidator createValidator(PublicKey publicKey) {
        BasicCredential credential = new BasicCredential();
        credential.setPublicKey(publicKey);
        return new SignatureValidator(credential);
    }

    public void checkAuthnInstant(Response samlResponse) throws Exception {
        Assertion assertion = samlResponse.getAssertions().get(0);
        AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
        DateTime authnInstant = authnStatement.getAuthnInstant();
        log.info("AuthnInstant[{}]", authnInstant);
        showAssersionAuthnStatement(assertion);
        DateTime validTime = authnInstant.plusMinutes(600);
        if (DateTime.now().compareTo(validTime) > 0) {
            throw new Exception("AuthnInstant time out : " + authnInstant);
        }
    }

    private void showAssersionAuthnStatement(Assertion assertion) {
        for (AuthnStatement authnStatement: assertion.getAuthnStatements()) {
            log.info(authnStatement.getSessionIndex());
            log.info(authnStatement.getDOM().toString());
        }
    }
}

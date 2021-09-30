package com.javafunc;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.xml.bind.DatatypeConverter;

import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

//import sun.security.provider.X509Factory;

/**
 * Azure Functions with HTTP Trigger.
 */
public class Function {

	private static final String EMPTY_STRING = "";

	//private static final String THUMBPRINT_APIM = "CAD5F4FAA167E153CE34AF0581F9F4C5B71B5FAB";
	private static final String THUMBPRINT_APIM = System.getenv().getOrDefault("THUMBPRINT_APIM", "<Enter_Thumbprint>");
	private static final String THUMBPRINT_POSTMAN = System.getenv().getOrDefault("THUMBPRINT_POSTMAN","<Enter_Thumbprint>");
	private static final String CN = "ENTER_CN";
	
	private X509Certificate x509Certificate;

	/**
	 * This function listens at endpoint "/api/certauth". 
	 * @throws NoSuchAlgorithmException 
	 * @throws CertificateEncodingException 
	 */
	@FunctionName("certauth")
	public HttpResponseMessage run(@HttpTrigger(name = "req", methods = { HttpMethod.GET,
			HttpMethod.POST }, authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
			final ExecutionContext context) throws CertificateEncodingException, NoSuchAlgorithmException {

		context.getLogger().info("Java HTTP trigger is processing the 'certauth' request.");

		Map<String, String> reqHeaders = request.getHeaders();

		String clientCert = reqHeaders.get("x-arr-clientcert");
		System.out.println("ClientCert is: " + clientCert);
		context.getLogger().info("ClientCert is: " + clientCert);	

		try {
			createX509Cert(clientCert);
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		
		CertAuthResponse response = new CertAuthResponse();
		response.setHeaders(reqHeaders);
		

		X509Certificate x509cert = getCertificate();
		
		response.setMessage("Certificate Validation successful");
		response.setIssuer(x509cert.getIssuerDN().getName());
		response.setSerialNumber(x509cert.getSerialNumber());
		response.setCn(x509cert.getIssuerDN().getName());
		
		if(!thumbprintIsValid())
		{
			response.setMessage("Certificate Validation Failed - Configured Thumb print does not match the passed cert: " + this.getCertDigest());
			return request.createResponseBuilder(HttpStatus.UNAUTHORIZED).body(response).build();
		}
		
		if(!certificateHasNotExpired())
		{
			response.setMessage("Certificate Validation Failed - Certificate Expired");
			return request.createResponseBuilder(HttpStatus.UNAUTHORIZED).body(response).build();
		}
		
		
		if(!x509cert.getIssuerDN().getName().contains(CN))
		{
			response.setMessage("Certificate Validation Failed - Issuer Name does not match");
			return request.createResponseBuilder(HttpStatus.UNAUTHORIZED).body(response).build();
		}
		
		return request.createResponseBuilder(HttpStatus.OK).body(response).build();
		
	}

	private void createX509Cert(String clientCert) throws CertificateException {
	//	clientCert = clientCert.replaceAll(X509Factory.BEGIN_CERT, EMPTY_STRING).replaceAll(X509Factory.END_CERT, EMPTY_STRING);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		byte[] base64Bytes = Base64.getDecoder().decode(clientCert);
		x509Certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(base64Bytes));
		this.setCertificate(x509Certificate);

	}
	
	 /**
     * Check certificate's timestamp.
     * @return Returns true if the certificate has not expired. Returns false if it has expired.
     */
    private boolean certificateHasNotExpired() {
        Date currentTime = new java.util.Date();
        try {
            this.getCertificate().checkValidity(currentTime);
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return false;
        }
        return true;
    }

	private List<String> getAllowedThumbprints() {
		List<String> thumbPrints = new ArrayList<>();		
	
		thumbPrints.add(THUMBPRINT_APIM.toLowerCase());
		thumbPrints.add(THUMBPRINT_POSTMAN.toLowerCase());

		return thumbPrints;

	}
	
	   
    /**
     * Check the certificate's thumbprint matches the given one.
     * @return Returns true if the thumbprints match. False otherwise.
     */
    private boolean thumbprintIsValid() throws NoSuchAlgorithmException, CertificateEncodingException {
        String digestHex = getCertDigest();
        
        System.out.println("*** digestHex is: " + digestHex);
        
        return this.getAllowedThumbprints().contains(digestHex.toLowerCase());
        
    }

	private String getCertDigest() throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = this.getCertificate().getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String digestHex = DatatypeConverter.printHexBinary(digest);
		return digestHex;
	}
	
	private void getCN() throws CertificateException {
		this.getCertificate().getSubjectX500Principal().getName();

	}
	
	public X509Certificate getCertificate() {
        return x509Certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.x509Certificate = certificate;
    }
 
}

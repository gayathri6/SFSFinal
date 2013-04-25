package com.sfs.test;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;


public class TestGPM {

	public static void main(String args[])
	{
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			KeyPair KPair = keyPairGenerator.generateKeyPair();
			
			X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator(); 
			v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	        v3CertGen.setIssuerDN(new X509Principal("C=US, ST=GA, L=Atlanta, O=SFS, CN=SFS CA/emailAddress=gayathri6@gatech.edu"));
	        v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
	        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365*10)));
	        v3CertGen.setSubjectDN(new X509Principal("CN=SFS Server, ST=GA, C=US/emailAddress=gayathri.rad@gmail.com, O=SFS"));

	        v3CertGen.setPublicKey(KPair.getPublic());
	        
	        
	        
	       

	        
	        
	        
	        KeyStore ks = KeyStore.getInstance("PKCS12");
	        FileInputStream fis = new FileInputStream("ca.p12");
	        ks.load(fis, "ca@8903".toCharArray());

	        Enumeration aliasEnum = ks.aliases();

	        Key key = null;
	        Certificate cert = null;

	        
	        key = ks.getKey("caCert","ca@8903".toCharArray());
	        cert = ks.getCertificate("caCert");
	       

	        KeyPair kp = new KeyPair(cert.getPublicKey(),(PrivateKey)key);
	        
	        v3CertGen.setSignatureAlgorithm("MD5withRSAEncryption");
	        X509Certificate finalRetCertficate = v3CertGen.generateX509Certificate((PrivateKey) key);

	        
	        pemEncodeToFile("serverCert.pem" , finalRetCertficate , null);
	        
	        

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		

	}
	
	
	 public static void pemEncodeToFile(String filename, Object obj, char[] password) throws Exception{
		    PEMWriter pw = new PEMWriter(new FileWriter(filename));
		       if (password != null && password.length > 0) {
		           pw.writeObject(obj, "DESEDE", password, new SecureRandom());
		       } else {
		           pw.writeObject(obj);
		       }
		       pw.flush();
		       pw.close();
		    }
}

package com.sfs.util;

public class Properties {

	public static final String clientCertslocation = "./client/certs/";
	public static final String clientPrivCertslocation = "./client/certs/private/";
	public static final String serverCertslocation = "./server/certs/";
	public static final String serverPrivCertslocation = "./server/certs/private/";
	public static final String clientKeyStoreLocation = "./client/ks/";
	public static final String serverKeyStoreLocation = "./server/ks/";
	public static final String newCertCommand = "NEWCERT";
	public static final int publicKEncodedSize = 162;
	public static final String caKeystorePwd = "ca@8903";
	public static final String caKeystore = "./ca/ca.p12";
	public static final String issuerDN = "C=US, ST=GA, L=Atlanta, O=SFS, CN=SFS CA/emailAddress=gayathri6@gatech.edu";
	public static final String subjectDN = "CN=%s, ST=GA, C=US/emailAddress=gayathri.rad@gmail.com, O=SFS";
	public static final int certGenSuccess = 101;
	public static final int certGenFailure = 501;
	public static final int caPort = 9999;
	public static final String checkRevCert = "CHECKREVCERT";
	public static final String crlFile = "./ca/crl/crl.txt";
	
}

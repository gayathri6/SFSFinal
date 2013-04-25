package com.sfs;
/**
 * SslSocketClientRevised.java
 * Copyright (c) 2005 by Dr. Herong Yang
 */
import java.io.*;
import java.io.ObjectInputStream.GetField;

import com.sfs.util.*;

import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.*;

import org.apache.log4j.Logger;
import org.bouncycastle.openssl.PEMReader;
public class SFSClient {

	private static Logger logger = Logger.getLogger(SFSClient.class);
	private static String clientName;
<<<<<<< HEAD
	
=======

>>>>>>> CRL implementation
	public static void main(String[] args) {

		if (args.length<2) {
<<<<<<< HEAD
	         System.out.println("Usage:");
	         System.out.println(
	            "java SFSClient <hostname> <keystorePassword>");
	         return;
	      }
		clientName = args[0];
		
=======
			System.out.println("Usage:");
			System.out.println(
					"java SFSClient <hostname> <keystorePassword>");
			return;
		}
		clientName = args[0];

>>>>>>> CRL implementation
		// Check if certificate keystore exists , if not request one from the CA
		String fileName = Properties.clientCertslocation + clientName + ".cer";
		try {
			Socket caClient = new Socket("localhost",Properties.caPort);
			if(!(Utilities.checkIfFileExists(fileName)))
			{
				// File does not exist, talk to the CA
				logger.info("File does not exist, talk to the CA for " + clientName);
				BufferedReader socketReader =  new BufferedReader( new InputStreamReader( caClient.getInputStream () )  );        
				PrintStream caClientSocketWriter = new PrintStream( caClient.getOutputStream ()  );

				caClientSocketWriter.println(Properties.newCertCommand + ":" + clientName);


				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
				keyPairGenerator.initialize(1024);
				KeyPair KPair = keyPairGenerator.generateKeyPair();

				String privKeyFileName = Properties.clientPrivCertslocation + clientName + ".pem";
				String keyStorePassword = "sfs" + clientName;
				Utilities.pemEncodeToFile(privKeyFileName, KPair.getPrivate(), null);
				PublicKey publicK = KPair.getPublic();

				logger.info("Public key for client " + clientName + "is :" + publicK.toString());

				byte[] publicKByteArr = publicK.getEncoded();
				logger.info("Size :" + publicKByteArr.length);

				DataOutputStream dataOut = new DataOutputStream(caClient.getOutputStream());
				dataOut.write(publicKByteArr);
				caClientSocketWriter.flush();


				// Check if certificate was generated successfully

				int certGenStatus = Integer.parseInt(socketReader.readLine());
				if(certGenStatus == Properties.certGenSuccess)
				{
					logger.info("Certificate generated successfully");


					/*	byte[] certBytes = new byte[certGenLength];*/
					DataInputStream clientReader = new DataInputStream(caClient.getInputStream());
					int certGenLength = clientReader.readInt();
					logger.info("Certificate length :" + certGenLength);
					// int byteCount = clientReader.read(certBytes);
					byte[] certByte = new byte[certGenLength];
					for(int i=0;i<certGenLength;i++)
					{
						certByte[i] = clientReader.readByte();
					}
					File targetFile = new File(fileName);
					FileOutputStream fos = new FileOutputStream(targetFile);
					fos.write(certByte, 0, certGenLength);
					fos.close();


					// Create the keystore

					KeyStore ks = KeyStore.getInstance("JKS");
					ks.load( null, null ); 
					FileInputStream fis = new FileInputStream(fileName); 
					BufferedInputStream bis = new BufferedInputStream(fis); 
					CertificateFactory cf = CertificateFactory.getInstance( "X.509" ); 
					Certificate cert = null; 
					cert = cf.generateCertificate( bis );  
					ks.setCertificateEntry( clientName + "Cert", cert ); 





					DataInputStream sclientReader = new DataInputStream(caClient.getInputStream());
					int serverCertGenLength = sclientReader.readInt();
					logger.info("Certificate length :" + serverCertGenLength);
					//int sbyteCount = clientReader.read(serCertBytes);
					byte[] scertByte = new byte[serverCertGenLength];
					for(int i=0;i<serverCertGenLength;i++)
					{
						scertByte[i] = sclientReader.readByte();
					}


					CertificateFactory scf = CertificateFactory.getInstance( "X.509" ); 
					Certificate certificate = scf.generateCertificate(new ByteArrayInputStream(scertByte));

					ks.setCertificateEntry( "serverCert", certificate ); 
					String ksFile = Properties.clientKeyStoreLocation + clientName + ".jks";
					ks.store( new FileOutputStream( ksFile ), args[1].toCharArray() );  

				}

				else
				{
					logger.error("Error in certificate generation");
				}



			}
			else
			{
				// Client certificate does not exist , check if server certificate has been revoked
				KeyStore clientKeyStore = KeyStore.getInstance( "JKS" );
				String ksFile = Properties.clientKeyStoreLocation + clientName + ".jks";
				FileInputStream fileInputStream = new FileInputStream(ksFile);
				clientKeyStore.load( fileInputStream, args[1].toCharArray() );
				fileInputStream.close();
				X509Certificate serverCert = (X509Certificate)clientKeyStore.getCertificate( "serverCert");

				BigInteger serialNumber = serverCert.getSerialNumber();
				logger.info("Serial Number of the server certificate in client.jks" + serialNumber.toString());
				PrintStream caClientSocketWriter = new PrintStream( caClient.getOutputStream ()  );

				caClientSocketWriter.println(Properties.checkRevCert + ":" + clientName + ":" + serialNumber);
				caClientSocketWriter.flush();

				logger.info("Reading server certificate, fingers crossed!");

				DataInputStream clientReader = new DataInputStream(caClient.getInputStream());
				int revStatus = clientReader.readInt();
				if(revStatus == 1)
				{
					logger.info("Server certificate has been revoked");
					int certLength = clientReader.readInt();
					logger.info("Certificate length :" + certLength);
					byte[] certByte = new byte[certLength];
					for(int i=0;i<certLength;i++)
					{
						certByte[i] = clientReader.readByte();
					}
					logger.info("Received the entire server certificate!!!!!");

					logger.info("Generating server certificate from byte stream");
					CertificateFactory cf = CertificateFactory.getInstance( "X.509" ); 
					Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certByte));
					logger.info("Server certificate generated!");

					logger.info("Updating client keystore with the new server Certificate");
					Utilities.updateClientKeyStore(clientName, args[1], cert);
					logger.info("Updated!");
				}
				else
					logger.info("Server certificate has not been revoked");

				// int byteCount = clientReader.read(certBytes);

			}
			caClient.close();
		}

		catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  






		logger.info("Certificate exists : Client Side");

		try
		{ 
			String certfileName = Properties.clientCertslocation + clientName + ".cer";
			FileInputStream inputStream = new FileInputStream(certfileName);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);
			String privKeyFileName = Properties.clientPrivCertslocation + clientName + ".pem";
			PEMReader kr = new PEMReader(new FileReader(privKeyFileName), null);
			KeyPair key = (KeyPair) kr.readObject();
			KeyStore ksKeys = KeyStore.getInstance("JKS");
			String ksFile = Properties.clientKeyStoreLocation + clientName + ".jks";

			ksKeys.load(new FileInputStream(ksFile),args[1].toCharArray());            
			ksKeys.setCertificateEntry(clientName + "Cert", cert);                        
			ksKeys.setKeyEntry(clientName + "Cert", key.getPrivate(),args[1].toCharArray(), new Certificate[]{cert});                                    
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ksKeys, args[1].toCharArray());
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(ksKeys);
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			SocketFactory factory = sslContext.getSocketFactory();
			SSLSocket client = (SSLSocket)factory.createSocket("localhost",9997);     
			client.setNeedClientAuth(true);  
			client.startHandshake();
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
					client.getOutputStream()));
			BufferedReader r = new BufferedReader(new InputStreamReader(
					client.getInputStream()));			
			logger.info("Client connected");
			//begin handling requests
			System.out.println("Enter command (get/put/delegate):");
			String command = in.readLine();
			if (command.equals("get")) {
				String comString = get();
				w.write(comString, 0, comString.length());
				w.newLine();
				w.flush();
				System.out.println(r.readLine());//printout the results returned
			} else if (command.equals("put")) {
				String comString = put();
				w.write(comString, 0, comString.length());
				w.newLine();
				w.flush();
				System.out.println(r.readLine());//printout the results returned
			} else if (command.equals("delegate")) {
				String comString = delegate();
				w.write(comString, 0, comString.length());
				w.newLine();
				w.flush();
				System.out.println(r.readLine());//printout the results returned
			} else {
				System.out.println("Command not recognized!");
			}
			w.close();
			r.close();
			client.close();
		} catch (Exception e) {
			System.err.println(e.toString());
		}

	}

	// clientName command additional1(filename or username) additional2(file contents)
	private static String get() {
		try {
			BufferedReader stdinp = new BufferedReader(new InputStreamReader(
					System.in));
			System.out
			.println("Enter filename (do NOT include file extenstion):");
			String filename = stdinp.readLine();
			return clientName + " get " + filename.trim();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "error!";
		}
	}

	private static String put() {
		try {
			BufferedReader stdinp = new BufferedReader(new InputStreamReader(
					System.in));
			System.out
			.println("Enter filename (do NOT include file extenstion):");
			String filename = stdinp.readLine();
			BufferedReader br = new BufferedReader(new FileReader(filename + ".txt"));
			String fileText = "";
			String inputLine;
			while ((inputLine = br.readLine()) != null) {
				fileText += inputLine + "\n";
			}
			String transText = fileText.replaceAll(" ", "_");			
			System.out.println("Test: " + transText);//test line

			return clientName + " put " + filename.trim() + " " + transText;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "error!";
		}
	}

<<<<<<< HEAD
		
			  logger.info("Certificate exists : Client Side");
		      
			  try
		        { 
	  			  String certfileName = Properties.clientCertslocation + clientName + ".cer";
		            FileInputStream inputStream = new FileInputStream(certfileName);
		            CertificateFactory cf = CertificateFactory.getInstance("X.509");
		            X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);
		            String privKeyFileName = Properties.clientPrivCertslocation + clientName + ".pem";
		            PEMReader kr = new PEMReader(new FileReader(privKeyFileName), null);
		            KeyPair key = (KeyPair) kr.readObject();
		            KeyStore ksKeys = KeyStore.getInstance("JKS");
		            String ksFile = Properties.clientKeyStoreLocation + clientName + ".jks";
		            
		            ksKeys.load(new FileInputStream(ksFile),args[1].toCharArray());            
		            ksKeys.setCertificateEntry(clientName + "Cert", cert);                        
		            ksKeys.setKeyEntry(clientName + "Cert", key.getPrivate(),args[1].toCharArray(), new Certificate[]{cert});                                    
		            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		            kmf.init(ksKeys, args[1].toCharArray());
		            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		            tmf.init(ksKeys);
		            SSLContext sslContext = SSLContext.getInstance("TLS");
		            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		            SocketFactory factory = sslContext.getSocketFactory();
		            SSLSocket client = (SSLSocket)factory.createSocket("localhost",9997);     
		            client.setNeedClientAuth(true);  
		            client.startHandshake();
					BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
					BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
							client.getOutputStream()));
					BufferedReader r = new BufferedReader(new InputStreamReader(
							client.getInputStream()));			
		            logger.info("Client connected");
//begin handling requests
					System.out.println("Enter command (get/put/delegate):");
					String command = in.readLine();
					if (command.equals("get")) {
						String comString = get();
						w.write(comString, 0, comString.length());
						w.newLine();
						w.flush();
						System.out.println(r.readLine());//printout the results returned
					} else if (command.equals("put")) {
						String comString = put();
						w.write(comString, 0, comString.length());
						w.newLine();
						w.flush();
						System.out.println(r.readLine());//printout the results returned
					} else if (command.equals("delegate")) {
						String comString = delegate();
						w.write(comString, 0, comString.length());
						w.newLine();
						w.flush();
						System.out.println(r.readLine());//printout the results returned
					} else {
						System.out.println("Command not recognized!");
					}
					w.close();
					r.close();
					client.close();
				} catch (Exception e) {
					System.err.println(e.toString());
				}
		        
=======
	private static String delegate() {
		try {
			BufferedReader stdinp = new BufferedReader(new InputStreamReader(
					System.in));
			System.out
			.println("Enter filename (do NOT include file extenstion):");
			String filename = stdinp.readLine();
			System.out.println("Enter user to add:");
			String newUser = stdinp.readLine();
			return clientName + " delegate " + filename.trim() + " "
			+ newUser.trim();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "error!";
>>>>>>> CRL implementation
		}
	}

<<<<<<< HEAD
	// clientName command additional1(filename or username) additional2(file contents)
		private static String get() {
			try {
				BufferedReader stdinp = new BufferedReader(new InputStreamReader(
						System.in));
				System.out
						.println("Enter filename (do NOT include file extenstion):");
				String filename = stdinp.readLine();
				return clientName + " get " + filename.trim();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "error!";
			}
		}

		private static String put() {
			try {
				BufferedReader stdinp = new BufferedReader(new InputStreamReader(
						System.in));
				System.out
						.println("Enter filename (do NOT include file extenstion):");
				String filename = stdinp.readLine();
				BufferedReader br = new BufferedReader(new FileReader(filename + ".txt"));
				String fileText = "";
				String inputLine;
				while ((inputLine = br.readLine()) != null) {
					fileText += inputLine + "\n";
				}
				String transText = fileText.replaceAll(" ", "_");			
				System.out.println("Test: " + transText);//test line
				
				return clientName + " put " + filename.trim() + " " + transText;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "error!";
			}
		}

		private static String delegate() {
			try {
				BufferedReader stdinp = new BufferedReader(new InputStreamReader(
						System.in));
				System.out
						.println("Enter filename (do NOT include file extenstion):");
				String filename = stdinp.readLine();
				System.out.println("Enter user to add:");
				String newUser = stdinp.readLine();
				return clientName + " delegate " + filename.trim() + " "
						+ newUser.trim();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "error!";
			}
		}
	
=======
>>>>>>> CRL implementation
	private static void printSocketInfo(SSLSocket s) {
		System.out.println("Socket class: "+s.getClass());
		System.out.println("   Remote address = "
				+s.getInetAddress().toString());
		System.out.println("   Remote port = "+s.getPort());
		System.out.println("   Local socket address = "
				+s.getLocalSocketAddress().toString());
		System.out.println("   Local address = "
				+s.getLocalAddress().toString());
		System.out.println("   Local port = "+s.getLocalPort());
		System.out.println("   Need client authentication = "
				+s.getNeedClientAuth());
		SSLSession ss = s.getSession();
		try {
			System.out.println("Session class: "+ss.getClass());
			System.out.println("   Cipher suite = "
					+ss.getCipherSuite());
			System.out.println("   Protocol = "+ss.getProtocol());
			System.out.println("   PeerPrincipal = "
					+ss.getPeerPrincipal().getName());
			System.out.println("   LocalPrincipal = "
					+ss.getLocalPrincipal().getName());
			System.out.println("   PeerPrincipal = "
					+ss.getPeerPrincipal().getName());
		} catch (Exception e) {
			System.err.println(e.toString());
		}
	}
}
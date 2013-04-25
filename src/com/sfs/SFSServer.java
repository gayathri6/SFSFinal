package com.sfs;
/**
 * SslReverseEchoerRevised.java
 * Copyright (c) 2005 by Dr. Herong Yang
 */
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.*;

import org.apache.log4j.Logger;
import org.bouncycastle.openssl.PEMReader;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import com.sfs.util.Properties;
import com.sfs.util.Utilities;
public class SFSServer {
	
	private static Logger logger = Logger.getLogger(SFSServer.class);
	private static PublicKey pubKey;
   public static void main(String[] args) {
	   
	   if (args.length<2) {
	         System.out.println("Usage:");
	         System.out.println("java SFSServer <serverName> <keystorePassword>");
	         return;
	      }
	   
	   String serverName = args[0];
	   String fileName = Properties.serverCertslocation + serverName + ".cer";
		if(!(Utilities.checkIfFileExists(fileName)))
		{
			// File does not exist, talk to the CA
			logger.info("File does not exist, talk to the CA for " + serverName);

			Socket caServer;
			try {
				caServer = new Socket("localhost",Properties.caPort);
				BufferedReader socketReader =  new BufferedReader(new InputStreamReader(caServer.getInputStream ()));        
				PrintStream caServerSocketWriter = new PrintStream(caServer.getOutputStream());

				caServerSocketWriter.println(Properties.newCertCommand + ":" + serverName);


				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
				keyPairGenerator.initialize(1024);
				KeyPair KPair = keyPairGenerator.generateKeyPair();

				String privKeyFileName = Properties.serverPrivCertslocation + serverName + ".pem";
				String keyStorePassword = "sfs" + serverName;
				Utilities.pemEncodeToFile(privKeyFileName, KPair.getPrivate(), null);
				PublicKey publicK = KPair.getPublic();
				pubKey = publicK;
				logger.info("Public key for server " + serverName + "is :" + publicK.toString());

				byte[] publicKByteArr = publicK.getEncoded();
				logger.info("Size :" + publicKByteArr.length);



				DataOutputStream dataOut = new DataOutputStream(caServer.getOutputStream());
				dataOut.write(publicKByteArr);
				caServerSocketWriter.flush();

				
				// Check if certificate was generated successfully
				
				int certGenStatus = Integer.parseInt(socketReader.readLine());
				if(certGenStatus == Properties.certGenSuccess)
				{
					logger.info("Certificate generated successfully");
					DataInputStream clientReader = new DataInputStream(caServer.getInputStream());
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
	                ks.setCertificateEntry( serverName + "Cert", cert ); 
	                String ksFile = Properties.serverKeyStoreLocation + serverName + ".jks";
	                ks.store( new FileOutputStream( ksFile ), args[1].toCharArray() );  
	                
				}
					
				else
				{
					logger.error("Error in certificate generation");
				}
				caServer.close();


			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}  
		}

		logger.info("Certificate exists : Server Side");
		int portNumber = 9997;
        try
        {     
        	String serverCert = Properties.serverCertslocation + serverName + ".cer";
            FileInputStream inputStream = new FileInputStream(serverCert);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);
          
            String privKeyFileName = Properties.serverPrivCertslocation + serverName + ".pem";
            PEMReader kr = new PEMReader(new FileReader(privKeyFileName), null);                         
            KeyPair key = (KeyPair) kr.readObject();
            PrivateKey serverPrivateKey = key.getPrivate();
            PublicKey serverPublicKey = key.getPublic();
			pubKey = serverPublicKey;
            KeyStore ksKeys = KeyStore.getInstance("JKS");
            String ksFile = Properties.serverKeyStoreLocation + "server.jks";
            ksKeys.load(new FileInputStream(ksFile),args[1].toCharArray());
            ksKeys.setCertificateEntry("serverCert", cert);                                                
            ksKeys.setKeyEntry("serverKey", key.getPrivate(),args[1].toCharArray(), new Certificate[]{cert});                        
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ksKeys, args[1].toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ksKeys);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            ServerSocketFactory factory = sslContext.getServerSocketFactory();
            ServerSocket serverSocket = (SSLServerSocket)factory.createServerSocket(portNumber);  
            logger.info("Server started at 9997");
			SSLSocket c;
          //**********************CHANGE ME PUBLIC KEY*********************
			//byte[] publicKey = pubKey.getEncoded();
			//byte[] publicKey = "awleiasdfafe".getBytes();
			byte[] publicKey = hasher(new String(pubKey.getEncoded()));
			System.out.println("Public Key: " + Arrays.toString(publicKey));
			//*****************************************************

			while (true) {
				c = (SSLSocket) serverSocket.accept();
				logger.info("Server: Accepted a connection");
				System.out.println("Accepted a connection"); // debug line

				BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
				BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
				String com = r.readLine();
				System.out.println("Command: " + com);//debug line
				String command[];
				command = com.split(" ");
				System.out.println("User: " + command[0]);
				// start of the parsing for commands
				if (command[1].equals("get")) {
					System.out.println("Went into get");
					File file = new File(command[2] + ".txt");
					File filemeta = new File(command[2] + "-meta.txt");
					if (file.exists() && filemeta.exists()) {
						try {
							String encTextMeta = "", plainTextMeta, plainText, encText;
							String metaData[];
							BufferedReader br = new BufferedReader(new FileReader(command[2] + "-meta.txt"));
							String inputLine;
							while ((inputLine = br.readLine()) != null) {
								encTextMeta += inputLine + "\n";
							}
							br.close();
							metaData = encTextMeta.split("\n");
							plainTextMeta = decrypt(metaData[0], publicKey);
							metaData[0] = plainTextMeta;
							System.out.println(Arrays.toString(metaData));//debug line
							boolean deny=true;
							for (int i = 1; i < metaData.length; ++i) {
								if (command[0].equals(metaData[i])) {
									deny=false;
									BufferedReader br2 = new BufferedReader(new FileReader(command[2] + ".txt"));
									encText = br2.readLine();
									br2.close();
									plainText = decrypt(encText, metaData[0].getBytes());
									w.write(plainText, 0, plainText.length());
									w.newLine();
									w.flush();
								}
							}
							if(deny){
								plainText = "You do not have access to this file!";
								w.write(plainText, 0, plainText.length());
								w.newLine();
								w.flush();
							}
						} catch (Exception e) {

						}
					}
				} else if (command[1].equals("put")) {
					System.out.println("Went into put");
					try {
						String encText;
						String encMeta;
						String fileText = command[3].replaceAll("_", " ");
						byte[] hash = hasher(fileText);
						System.out.println("finished hash");//debug line
						String hashString = new String(hash);
						// encrypt the file and the meta file
						encText = encrypt(fileText, hash);
						System.out.println("finished encrypt text");//debug line
						encMeta = encrypt(hashString, publicKey);
						System.out.println("finished encrypt meta");//debug line
						encMeta = encMeta  + "\n" + command[0];
						File file = new File(command[2] + ".txt");
						File filemeta = new File(command[2] + "-meta.txt");
						if (!file.exists()) {
							file.createNewFile();
						}
						if (!filemeta.exists()) {
							filemeta.createNewFile();
						}
						FileWriter fw = new FileWriter(file.getAbsoluteFile());
						FileWriter fw2 = new FileWriter(filemeta.getAbsoluteFile());
						BufferedWriter bw = new BufferedWriter(fw);
						BufferedWriter bw2 = new BufferedWriter(fw2);
						bw.write(encText);
						bw2.write(encMeta);
						bw.close();
						bw2.close();
						
						w.write("Successfully put " + command[2], 0, ("Successfully put " + command[2]).length());
						w.newLine();
						w.flush();
					} catch (Exception e) {
						System.out.println(e.getMessage());
					}
				} else if (command[1].equals("delegate")) {
					System.out.println("Went into delegate");
					File filemeta = new File(command[2] + "-meta.txt");
					if (filemeta.exists()) {
						try {
							String encTextMeta = "";
							String metaData[];
							BufferedReader br = new BufferedReader(new FileReader(command[2] + "-meta.txt"));
							String inputLine;
							while ((inputLine = br.readLine()) != null) {
								encTextMeta += inputLine + "\n";
							}
							br.close();
							metaData = encTextMeta.split("\n");
							System.out.println("meta: " + Arrays.toString(metaData));//debug line
							boolean deny = true;
							for (int i = 1; i < metaData.length; ++i) {
								if (command[0].equals(metaData[i])) {
									deny = false;
									encTextMeta = encTextMeta + "\n" + command[3];
									FileWriter fileWritter = new FileWriter(filemeta.getName());
									BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
									bufferWritter.write(encTextMeta);
									bufferWritter.close();
									
									w.write("Successfully added " + command[3], 0, ("Successfully added " + command[3]).length());
									w.newLine();
									w.flush();
								}
							}
							if(deny){
								String plainText = "You do not have access to that file";
								w.write(plainText, 0, plainText.length());
								w.newLine();
								w.flush();
							}
						} catch (Exception e) {

						}
					}
				} else {
					w.write("You made a type!", 0, ("You made a type!").length());
					w.newLine();
					w.flush();
				}
			}
        }
        catch(Exception ex)
        {
            System.out.println(ex.getMessage());
        }
   }
   
   public static String encrypt(String data, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		String strCipherText = new String();

		SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		Cipher aesCipher = Cipher.getInstance("AES");

		aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);

		byte[] byteDataToEncrypt = data.getBytes();
		byte[] byteCipherText = aesCipher.doFinal(byteDataToEncrypt);
		strCipherText = new BASE64Encoder().encode(byteCipherText);

		return strCipherText;
	}

	public static String decrypt(String cipherText, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
		String strDecryptedText = new String();
		SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] byteDecryptedText = aesCipher.doFinal(new BASE64Decoder().decodeBuffer(cipherText));
		strDecryptedText = new String(byteDecryptedText);
		return strDecryptedText;
	}

	public static byte[] hasher(String fi) {
		byte[] hash = { -1 };
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(fi.getBytes("UTF-8"));

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return hash;
	}
   
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
      } catch (Exception e) {
         System.err.println(e.toString());
      }
   }
   private static void printServerSocketInfo(SSLServerSocket s) {
      System.out.println("Server socket class: "+s.getClass());
      System.out.println("   Socker address = "
         +s.getInetAddress().toString());
      System.out.println("   Socker port = "
         +s.getLocalPort());
      System.out.println("   Need client authentication = "
         +s.getNeedClientAuth());
      System.out.println("   Want client authentication = "
         +s.getWantClientAuth());
      System.out.println("   Use client mode = "
         +s.getUseClientMode());
   } 
}
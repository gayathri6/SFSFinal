package com.sfs.ca;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;



import org.apache.log4j.Logger;

import com.sfs.util.Properties;
import com.sfs.util.Utilities;

public class SFSCAThread extends Thread {

	private Socket socket;
	private static Logger logger = Logger.getLogger(SFSCAThread.class);

	public SFSCAThread(Socket sock)
	{
		this.socket = sock;
	}

	public void run()
	{
		try {
			logger.info("Spawned a CA Worker thread on port : " + socket.getLocalPort());
			PrintStream writer = new PrintStream(socket.getOutputStream());


			BufferedReader din = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String[] commandInput = din.readLine().split(":");
			String command = commandInput[0];
			String fromHost = commandInput[1];
			switch(command)
			{

			case Properties.newCertCommand:
				logger.info("NewCert command issued from" + fromHost);
				logger.info("Reading public key from the host");

				DataInputStream byteReader = new DataInputStream(socket.getInputStream());
				byte[] publicKeyEncoded = new byte[Properties.publicKEncodedSize];
				byteReader.readFully(publicKeyEncoded);

				PublicKey recvdPublicKey = Utilities.getPublicKey(publicKeyEncoded);
				logger.info(recvdPublicKey.toString());

				// Generate and sign the certificate
				String subjectDN = String.format(Properties.subjectDN, fromHost);
				X509Certificate genCertificate = Utilities.generateCertificate(recvdPublicKey, subjectDN);

				if(genCertificate != null)
				{
					logger.info("Sending Certificate ...");
					writer.println(Properties.certGenSuccess);
					byte[] certBytes = genCertificate.getEncoded();

					DataOutputStream dataOutCert = new DataOutputStream(socket.getOutputStream());
					dataOutCert.writeInt(certBytes.length);
					//writer.println(serverCertBytes.length);
					dataOutCert.write(certBytes);
					dataOutCert.flush();
					//out.close();

					if(fromHost.contains("client"))
					{
						logger.info("Updating server key store ...");
						KeyStore serverkeyStore = KeyStore.getInstance( "JKS" );
						String serverksFile = Properties.serverKeyStoreLocation + "server.jks";
						FileInputStream fileInputStream = new FileInputStream(serverksFile);
						serverkeyStore.load( fileInputStream, "server".toCharArray() );
						fileInputStream.close();
						serverkeyStore.setCertificateEntry( fromHost + "Cert", genCertificate);

						FileOutputStream fileOutputStream = new FileOutputStream(serverksFile);
						serverkeyStore.store( fileOutputStream, "server".toCharArray() );
						fileOutputStream.close();

						logger.info("Sending the server certificate to the client keystore");

						String serverFileName = Properties.serverCertslocation + "server.cer";
						FileInputStream fis = new FileInputStream(serverFileName); 
						BufferedInputStream bis = new BufferedInputStream(fis); 
						CertificateFactory cf = CertificateFactory.getInstance( "X.509" ); 
						X509Certificate serverCert = (X509Certificate)cf.generateCertificate( bis );

						byte[] serverCertBytes = serverCert.getEncoded();
						DataOutputStream dataOut = new DataOutputStream(socket.getOutputStream());
						dataOut.writeInt(serverCertBytes.length);

						dataOut.write(serverCertBytes);
						dataOut.flush();



					}

				}

				else
				{
					writer.println(Properties.certGenFailure);
					logger.info("Unable to generate certificate");
				}
				Utilities.pemEncodeToFile(fromHost + ".pem" , genCertificate , null);
				break;

			case Properties.checkRevCert:
				logger.info("Command" + commandInput[0] + "issued from" + commandInput[1] + "serialNumber" + commandInput[2]);
				boolean revResult = Utilities.checkRevokedCert(commandInput[2]);	
				logger.info("Has server cert with serial number :" + commandInput[2] + "been revoked?" + revResult);
				DataOutputStream dataOutCert = new DataOutputStream(socket.getOutputStream());
				if(revResult)
				{
					dataOutCert.writeInt(1);
					X509Certificate serverCert =  Utilities.getServerCertificate();
					byte[] serverCertBytes = serverCert.getEncoded();
					DataOutputStream dataOut = new DataOutputStream(socket.getOutputStream());
					dataOut.writeInt(serverCertBytes.length);

					dataOut.write(serverCertBytes);
					dataOut.flush();
				}
				else
					dataOutCert.write(0);
				
				break;
			
				
			default:
				logger.info("Invalid command issued to the CA!");
			}
			socket.close();
			//logger.info(din.readLine());//debug  line;
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}

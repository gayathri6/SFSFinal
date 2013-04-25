import java.io.*;
import java.net.*;
import java.security.*;
import javax.net.ssl.*;

public class SslSocketClientRevised {
	private static String userid;

	public static void main(String[] args) {
		if (args.length < 3) {
			System.out.println("Usage:");
			System.out
					.println("   java SslReverseEchoerRevised ksName ksPass ctPass");
			return;
		}
		String ksName = args[0];
		char[] ksPass = args[1].toCharArray();
		char[] ctPass = args[2].toCharArray();
		userid = args[3];
		System.setProperty("javax.net.ssl.trustStore", args[0]);
		System.setProperty("javax.net.ssl.trustStorePassword", args[1]);
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		PrintStream out = System.out;
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(ksName), ksPass);
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, ctPass);
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(kmf.getKeyManagers(), null, null);
			SSLSocketFactory f = sc.getSocketFactory();
			SSLSocket c = (SSLSocket) f.createSocket("localhost", 8888);
			printSocketInfo(c);
			c.startHandshake();
			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
					c.getOutputStream()));
			BufferedReader r = new BufferedReader(new InputStreamReader(
					c.getInputStream()));			
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
			/*
			 * String m = null; while ((m=r.readLine())!= null) {
			 * out.println(m); m = in.readLine(); w.write(m,0,m.length());
			 * w.newLine(); w.flush(); }
			 */
			w.close();
			r.close();
			c.close();
		} catch (Exception e) {
			System.err.println(e.toString());
		}
	}

	// userid command additional1(filename or username) additional2(file contents)
	private static String get() {
		try {
			BufferedReader stdinp = new BufferedReader(new InputStreamReader(
					System.in));
			System.out
					.println("Enter filename (do NOT include file extenstion):");
			String filename = stdinp.readLine();
			return userid + " get " + filename.trim();
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
			
			return userid + " put " + filename.trim() + " " + transText;
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
			return userid + " delegate " + filename.trim() + " "
					+ newUser.trim();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "error!";
		}
	}

	private static void printSocketInfo(SSLSocket s) {
		System.out.println("Socket class: " + s.getClass());
		System.out.println("   Remote address = "
				+ s.getInetAddress().toString());
		System.out.println("   Remote port = " + s.getPort());
		System.out.println("   Local socket address = "
				+ s.getLocalSocketAddress().toString());
		System.out.println("   Local address = "
				+ s.getLocalAddress().toString());
		System.out.println("   Local port = " + s.getLocalPort());
		System.out.println("   Need client authentication = "
				+ s.getNeedClientAuth());
		SSLSession ss = s.getSession();
		try {
			System.out.println("Session class: " + ss.getClass());
			System.out.println("   Cipher suite = " + ss.getCipherSuite());
			System.out.println("   Protocol = " + ss.getProtocol());
			System.out.println("   PeerPrincipal = "
					+ ss.getPeerPrincipal().getName());
			System.out.println("   LocalPrincipal = "
					+ ss.getLocalPrincipal().getName());
			System.out.println("   PeerPrincipal = "
					+ ss.getPeerPrincipal().getName());
		} catch (Exception e) {
			System.err.println(e.toString());
		}
	}
}
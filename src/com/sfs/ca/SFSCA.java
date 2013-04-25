package com.sfs.ca;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

import org.apache.log4j.Logger;

import com.sfs.util.Properties;



public class SFSCA {

	private static Logger logger = Logger.getLogger(SFSCA.class);
	
	public static void main(String[] args) {
        Socket rSocket;
        int port = Properties.caPort;
        
        logger.info("Inside SFS CA");
        
        try {
        	
        	
        	ServerSocket caSocket = new ServerSocket(port);
        	logger.info("CA started at port " + port + "!");
            while (true) {
            	
            	// Spawn a worker thread for the CA
            	logger.info("Spawning");
            	new SFSCAThread(caSocket.accept()).start();
            	logger.info("Done");
              
            }
        } catch (SocketException se) {
        	logger.error(se);
        }catch (IOException e) {
            System.err.println(e);
        }
    }
}
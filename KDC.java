import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

public class KDC {
	
	public static String sessionKey;

	public static void main(String[] args) {
		
		PrintStream kdc_log;
		
		try {
			
			ServerSocket kdcSocket = new ServerSocket(3000);
			
			kdc_log = new PrintStream(new FileOutputStream(new File("./KDC_Log.txt"), true));
			
			String password = generatePassword(12);			//  creates 12 character long password
			
			kdc_log.println(getTimestamp() + " : " + password);				// password is added to the log file
			
			BufferedWriter pwdFile = new BufferedWriter(new FileWriter(new File("./passwd.txt")));
			
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(password.getBytes());
			byte[] digest = md.digest();
			
			String base64_pswd = Base64.getEncoder().encodeToString(digest);
			
			pwdFile.write(base64_pswd);				// base64 encoded password is written to the file
			
			pwdFile.close();
			
			getCertificate("Kdc");
			PrivateKey privKey = getPrivateKey("Kdc");
			
			Socket client = kdcSocket.accept();
			System.out.println("- - - - - - - - - -");
			System.out.println("Client connected ..");
			System.out.println("- - - - - - - - - -\n");
			
			getCertificate("Alice");
			sessionKey = generateSessionKey();		// session key is created when Alice is connected

			// send data to client
			DataOutputStream dos = new DataOutputStream(client.getOutputStream());
			// read data from client
			DataInputStream dis = new DataInputStream(client.getInputStream());
						
	        String text;
	        String p_a;
	        boolean comparePasswords = false;
	        
	        while (true) { 
	        	
	            try {
	                
	                if (dis.available() > 0){

	                	// read from client
	                	text = dis.readUTF();
	                	
	                	/* Alice->KDC : "Alice", Base64[P_KDC("Alice", Pass, "Mail", TS1)] */
						kdc_log.println(getTimestamp() + " Alice->KDC : " + text);
	                    
	                	String str = decrypt(text, privKey); 			// msg is decrypted with private key of KDC
	                	String server = str.split(",")[1];				// server id
	                	
	                	/* msg dec */
						kdc_log.println(getTimestamp() + " Message Decrypted : \"Alice\", " + str );
	                	
	                	String pswd = str.split(",")[0];
	                	comparePasswords = check(pswd);
	                	
	                	if (comparePasswords == false){
	                		System.out.println("Password Denied");
	                		dos.writeUTF("denied");
	                		
	                		/* KDC->Alice : "Password Denied" */
	                		kdc_log.println(getTimestamp() + " KDC->Alice : \"Password Denied\"" );
	                	}
	                	
	                	else if (comparePasswords == true){
	                		
	                		/* KDC->Alice : "Password Verified" */
	                		kdc_log.println(getTimestamp() + " KDC->Alice : \"Password Verified\"" );
	                	
		                    getCertificate(server);	
		                	
		                	String ts2 = getTimestamp();
		                    p_a = sessionKey + "," + "\"" + server + "\"" + "," + ts2;
		                    
		                    /* KDC->Alice : Base64[K_A], "Mail", [TS2] */
							kdc_log.println(getTimestamp() + " KDC->Alice : " + p_a );
		                    
		                    // send to client 
		                    dos.writeUTF(encrypt(p_a, "Alice") + "," + generateTicket(server, ts2));
		                    
		                    /* KDC->Alice : Base64[P_A(K_A, "Mail", TS2)], Base64[Ticket] */
							kdc_log.println(getTimestamp() + " KDC->Alice : " + encrypt(p_a, "Alice") + ", " + generateTicket(server, ts2));
	                	}
	                }
	                
	                if (comparePasswords == true){		// if passwords are mathced, close the connection with KDC server
	                	
		                // close connection 
		                dos.close(); 
		                dis.close(); 
		                kdcSocket.close(); 
		                client.close(); 
		      
		                System.out.println("Connection was closed!");
		                kdc_log.close();
		                
		                // terminate KDC server 
		                System.exit(0); 
	                }

	            } catch (Exception e) {

	                System.out.println("An exception occured!");
	                
	            }
	  
	        }
			
			
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}
	
	private static boolean check(String pswd) {
		
		boolean result = false;
		try {
			BufferedReader br = new BufferedReader(new FileReader("./passwd.txt"));
			String passInFile = br.readLine();
			br.close();
			
			byte[] p = Base64.getDecoder().decode(passInFile);
			
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(pswd.getBytes());
			byte[] mdigest = md.digest();
			
			if (Arrays.equals(p, mdigest))			// passwords are matched
				result = true;
			
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return result;
	}

	public static void getCertificate(String id){
		
		id = id.replace("\"", "");
		Certificate cert = new Certificate(id);
        cert.createKeys(id);
        if (!id.equals("Kdc")){
        	cert.certSignRequest(id);
        	cert.sign(id);
        }
        cert.createCert(id);
        
	}
	
	public static String getTimestamp(){
		return new SimpleDateFormat("dd.MM.yyyy HH:mm:ss").format(new Date());
	}
	
	public static String generateSessionKey() {			// generates a session key and return as base64 encoded string
		
		Key key = null;
		
		try {

			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			key = keyGen.generateKey();
		    
		} catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return new String(Base64.getEncoder().encodeToString(key.getEncoded()));
	      
	}
	
	public static String encrypt(String message, String certId) {
		
		byte[] encrypted_text = null;
		certId = certId.replace("\"", "");
		
		try {
			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(new FileInputStream("./cert/" + certId + ".cer"));
			PublicKey publicKey = certificate.getPublicKey();
		
			Cipher encrypt = Cipher.getInstance("RSA");
			encrypt.init(Cipher.ENCRYPT_MODE, publicKey);
			encrypted_text = encrypt.doFinal(message.getBytes());
			
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		return new String(Base64.getEncoder().encodeToString(encrypted_text));
	}

	public static String decrypt(String message, PrivateKey key) {		// returns password, server id and ts1
		
		String result = "";
		try {
			String base64_p_kdc = message.split(",")[1];
			byte[] p_kdc = Base64.getDecoder().decode(base64_p_kdc);
		
			Cipher decrypt = Cipher.getInstance("RSA");
			decrypt.init(Cipher.DECRYPT_MODE, key);
			String decrypted_text = new String(decrypt.doFinal(p_kdc));
			
			String passwd = decrypted_text.split(",")[1];
			String server = decrypted_text.split(",")[2];
			String ts1 = decrypted_text.split(",")[3];
			
			result += passwd + "," + server + "," + ts1;
			
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		return result;
		
	}
	
	public static String generateTicket(String serverName, String timestamp) {
		
		String ticket = "Alice" + "," + "\"" + serverName + "\"" + "," + timestamp + "," + sessionKey;
		return encrypt(ticket, serverName);
	}
	
	private static PrivateKey getPrivateKey(String id){
		
		PrivateKey privkey = null;
		try {
			
			BufferedReader br = new BufferedReader(new FileReader("./keys/key" + id + ".txt"));
			String encoded_key = br.readLine();
			byte[] byte_key = Base64.getDecoder().decode(encoded_key);
			
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			privkey = keyfactory.generatePrivate(new PKCS8EncodedKeySpec(byte_key));
			
			br.close();
			
		} catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			System.err.println("Error occured in :");
			e.printStackTrace();
		}
		return privkey;
		
	}

	private static String generatePassword(int len) {
		
	      String alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	      
	      String pwd = "";
	      
	      for(int i = 0; i < len; i++){
	    	  
	        int idx = (int)(alphanumeric.length() * Math.random()); 
	        pwd += alphanumeric.charAt(idx);
	        
	      }
	      return pwd;
	}
}

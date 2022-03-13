import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Alice {					// Client program

	public static void main(String[] args) {
		
		PrintStream alice_log;
		
		try {
			
			Scanner scan = new Scanner(System.in);
			
			System.out.print("Enter a password: ");
			String password = scan.nextLine();
			
			System.out.print("Which server do you want to connect? ");
			String server = scan.nextLine();
			server = "\"" + server + "\"";
			
			Socket kdcServer = new Socket("localhost", 3000);
			
			alice_log = new PrintStream(new FileOutputStream(new File("./Alice_Log.txt"), true));
	        
			// send data to the KDC server 
			DataOutputStream dos = new DataOutputStream(kdcServer.getOutputStream());
			// read data from the KDC server 
			DataInputStream dis = new DataInputStream(kdcServer.getInputStream());
			
			String ts1 = getTimestamp();
			String p_kdc = "Alice" + "," + password + "," + server + "," + ts1;
			
			/* Alice->KDC : "Alice", [Pass], "Mail", [TS1] */
			alice_log.println(getTimestamp() + " Alice->KDC : " + p_kdc);
			
			String enc_p_kdc = encrypt(p_kdc);			// returns base64 encoded string
			
            // send to the server 
            dos.writeUTF("Alice" + "," + enc_p_kdc);		// Alice, P_kdc
            
            /* Alice->KDC : "Alice", Base64[P_KDC("Alice", Pass, "Mail", TS1)]  */
            alice_log.println(getTimestamp() + " Alice->KDC : \"Alice\", " + enc_p_kdc);
            
			String ticket = null;
			String sessionKey = null;
			
			PrivateKey privKey;
			
	        try{

	            while (true){

	            	if (dis.available() > 0){
	
		                // receive from the server 
		                String response = dis.readUTF();
		                
		                // if password denied, ask again, else go on
		                if (response.equals("denied")){
					
		                	System.out.println("\n-----------------");
		        		System.out.println("Password Denied");
		                	
		                	/* KDC->Alice : "Password Denied"  */
		                	alice_log.println(getTimestamp() + " KDC->Alice : \"Password Denied\"");
		                	
		                	System.out.print("Enter a password: ");
		                	String newPassword = scan.nextLine();
		                	
		        		System.out.print("Which server do you want to connect? ");
		        		server = scan.nextLine();
		        			
		                	String new_p_kdc = "Alice" + "," + newPassword + "," + server + "," + ts1;
		                	
		                	/* Alice->KDC : "Alice", [Pass], "Mail", [TS1] */
		                	alice_log.println(getTimestamp() + " Alice->KDC : " + new_p_kdc );
		                	
		                	dos.writeUTF("Alice" + "," + encrypt(new_p_kdc));
		                	
		                	/* Alice->KDC : "Alice", Base64[P_KDC("Alice", Pass, "Mail", TS1)] */
		                	alice_log.println(getTimestamp() + " Alice->KDC : \"Alice\", " + encrypt(new_p_kdc));
		                }
		                
		                else {
		                	System.out.println("\n-----------------");
		        		System.out.println("Password Verified.");
		                	
		                	/* KDC->Alice : "Password Verified"  */
		                	alice_log.println(getTimestamp() + " KDC->Alice : \"Password Verified\"");
		                	
		                	/* KDC->Alice : Base64[P_A(K_A, "Mail", TS2)], Base64[Ticket] */ 
			                alice_log.println(getTimestamp() + " KDC->Alice : " + response);
			                
			                privKey = getPrivateKey("Alice"); 		// get the private key of Alice
			                
			                String p_a = response.split(",")[0];
			                sessionKey = decrypt(p_a, privKey).split(",")[0];
			                String ts2 = decrypt(p_a, privKey).split(",")[1];
			                
			                ticket = response.split(",")[1];
			                
			                /* Message Decrypted : Base64[K_A], "Mail", [TS2] */
					alice_log.println(getTimestamp() + " Message Decrypted : " + sessionKey + ", " + server + "," + ts2);
			                
			                // close connection. 
			            	dos.close(); 
			            	dis.close();
			            	kdcServer.close();
		                }
	            	}
	            	
	            }

	        } catch(Exception e){
	        	
	            System.out.println("KDC Server connection was closed.");
	        }
	        
			// send data to the server 
			DataOutputStream dosMail;
			DataOutputStream dosWeb;
			DataOutputStream dosDb;
			
			// read data from the server 
			DataInputStream disMail;
			DataInputStream disWeb;
			DataInputStream disDb;
			
			String message;
			SecureRandom random = new SecureRandom();
			int nonce = random.nextInt();					// generate a random nonce value
			
	        if (server.contains("Mail")) {
	        	
	        	Socket mailServer = new Socket("localhost", 3001);
	        	
	        	dosMail = new DataOutputStream(mailServer.getOutputStream());
	        	disMail = new DataInputStream(mailServer.getInputStream());
	        	
	        	// send Alice, Ticket, K_A(N1)
	        	dosMail.writeUTF("Alice" + "," + ticket + "," + sesKeyEnc(Integer.toString(nonce), sessionKey));
	        	
	        	/* Alice->Mail : "Alice", [N_1]  */
			alice_log.println(getTimestamp() + " Alice->Mail : \"Alice\", " + nonce);

			/* Alice->Mail : "Alice", Base64[Ticket], Base64[K_A(N_1)]  */
			alice_log.println(getTimestamp() + " Alice->Mail : \"Alice\", " + ticket + ", " + sesKeyEnc(Integer.toString(nonce), sessionKey));
	        	
			try{

		            while (true){

		            	if (disMail.available() > 0){
		
			                // receive from the server 
			                message = disMail.readUTF();
			                
			                /* Mail->Alice : Base64[K_A(N1+1, N2)] */
			                alice_log.println(getTimestamp() + " Mail->Alice : " + message);
			                
			                String decrypted = sesKeyDec(message, sessionKey);
			                
			                if (decrypted.split(",")[0].equals(Integer.toString(nonce+1))){		// verify the nonce value
			                	
			                	int nonce2 = Integer.parseInt(decrypted.split(",")[1]) + 1;			// nonce2 = N2 + 1
			                	
			                	/* Message Decrypted : N1 is OK, N2=[N2] */
			                	alice_log.println(getTimestamp() + " Message Decrypted : N1 is OK, N2=" + Integer.toString(nonce2-1));
			                	
			                	/* Alice->Mail : [N2+1] */
						alice_log.println(getTimestamp() + "Alice->Mail : " + Integer.toString(nonce2));
								
						dosMail.writeUTF("step5" + "," + sesKeyEnc(Integer.toString(nonce2), sessionKey));		// send N2+1 back to server
			                	
						/* Alice->Mail : Base64[K_A(N2+1)]  */
						alice_log.println(getTimestamp() + " Alice->Mail : " + sesKeyEnc(Integer.toString(nonce2), sessionKey));
			                }
			                
			                System.out.println("\n- - - - - - - - - -");
			                System.out.println("Authentication is completed!");
			                
			                /* Mail->Alice : "Authentication is completed!"  */
					alice_log.println(getTimestamp() + " Mail->Alice : " + "Authentication is completed!");
							
					alice_log.close();
					break;
		            	}
		            	
		            }
		            
		            System.exit(0);

		        } catch(Exception e){

		            	// close connection. 
		        	dosMail.close(); 
		        	disMail.close();
		            	mailServer.close();
		        }
	        	
	        }
	        else if (server.contains("Web")) {
	        	
	        	Socket webServer = new Socket("localhost", 3002);
	        	
	        	dosWeb = new DataOutputStream(webServer.getOutputStream());
	        	disWeb = new DataInputStream(webServer.getInputStream());

	        	// send Alice, Ticket, K_A(N1)
	        	dosWeb.writeUTF("Alice" + "," + ticket + "," + sesKeyEnc(Integer.toString(nonce), sessionKey));
	        	
	        	/* Alice->Web : "Alice", [N_1]  */
			alice_log.println(getTimestamp() + " Alice->Web : \"Alice\", " + nonce);

			/* Alice->Web : "Alice", Base64[Ticket], Base64[K_A(N_1)]  */
			alice_log.println(getTimestamp() + " Alice->Web : \"Alice\", " + ticket + ", " + sesKeyEnc(Integer.toString(nonce), sessionKey));
	        	
	        	try{

		            while (true){

		            	if (disWeb.available() > 0){
		
		            		// receive from the server 
			                message = disWeb.readUTF();
			                
			                /* Web->Alice : Base64[K_A(N1+1, N2)] */
			                alice_log.println(getTimestamp() + " Web->Alice : " + message);
			                
			                String decrypted = sesKeyDec(message, sessionKey);
			                
			                if (decrypted.split(",")[0].equals(Integer.toString(nonce+1))){		// verify the nonce value
			                	
			                	int nonce2 = Integer.parseInt(decrypted.split(",")[1]) + 1;			// nonce2 = N2 + 1
			                	
			                	/* Message Decrypted : N1 is OK, N2=[N2] */
			                	alice_log.println(getTimestamp() + " Message Decrypted : N1 is OK, N2=" + Integer.toString(nonce2-1));
			                	
			                	/* Alice->Web : [N2+1] */
						alice_log.println(getTimestamp() + "Alice->Web : " + Integer.toString(nonce2));
								
						dosWeb.writeUTF("step5" + "," + sesKeyEnc(Integer.toString(nonce2), sessionKey));		// send N2+1 back to server
			                	
						/* Alice->Web : Base64[K_A(N2+1)]  */
						alice_log.println(getTimestamp() + " Alice->Web : " + sesKeyEnc(Integer.toString(nonce2), sessionKey));
			                }
			                
			                System.out.println("\n- - - - - - - - - -");
			                System.out.println("Authentication is completed!");
			                
			                /* Web->Alice : "Authentication is completed!"  */
					alice_log.println(getTimestamp() + " Web->Alice : " + "Authentication is completed!");
							
					alice_log.close();
					break;
		            	}
		            	
		            }
		            
		            System.exit(0);

		        } catch(Exception e){

		            	// close connection. 
		        	dosWeb.close(); 
		            	disWeb.close();
		            	webServer.close();
		        }
	        	
	        }
	        else if (server.contains("Database")) {
	        	
	        	Socket dbServer = new Socket("localhost", 3003);
	        	
	        	dosDb = new DataOutputStream(dbServer.getOutputStream());
	        	disDb = new DataInputStream(dbServer.getInputStream());

	        	// send Alice, Ticket, K_A(N1)
	        	dosDb.writeUTF("Alice" + "," + ticket + "," + sesKeyEnc(Integer.toString(nonce), sessionKey));
	        	
	        	/* Alice->Database : "Alice", [N_1]  */
			alice_log.println(getTimestamp() + " Alice->Database : \"Alice\", " + nonce);

			/* Alice->Database : "Alice", Base64[Ticket], Base64[K_A(N_1)]  */
			alice_log.println(getTimestamp() + " Alice->Database : \"Alice\", " + ticket + ", " + sesKeyEnc(Integer.toString(nonce), sessionKey));
	        	
	        	try{

		            while (true){

		            	if (disDb.available() > 0){
		
		            		// receive from the server 
			                message = disDb.readUTF();
			                
			                /* Database->Alice : Base64[K_A(N1+1, N2)] */
			                alice_log.println(getTimestamp() + " Database->Alice : " + message);
			                
			                String decrypted = sesKeyDec(message, sessionKey);
			                
			                if (decrypted.split(",")[0].equals(Integer.toString(nonce+1))){		// verify the nonce value
			                	
			                	int nonce2 = Integer.parseInt(decrypted.split(",")[1]) + 1;			// nonce2 = N2 + 1
			                	
			                	/* Message Decrypted : N1 is OK, N2=[N2] */
			                	alice_log.println(getTimestamp() + " Message Decrypted : N1 is OK, N2=" + Integer.toString(nonce2-1));
			                	
			                	/* Alice->Database : [N2+1] */
						alice_log.println(getTimestamp() + "Alice->Database : " + Integer.toString(nonce2));
								
						dosDb.writeUTF("step5" + "," + sesKeyEnc(Integer.toString(nonce2), sessionKey));		// send N2+1 back to server
			                	
						/* Alice->Database : Base64[K_A(N2+1)]  */
						alice_log.println(getTimestamp() + " Alice->Database : " + sesKeyEnc(Integer.toString(nonce2), sessionKey));
			                }
			                
			                System.out.println("\n- - - - - - - - - -");
			                System.out.println("Authentication is completed!");
			                
			                /* Database->Alice : "Authentication is completed!"  */
					alice_log.println(getTimestamp() + " Database->Alice : " + "Authentication is completed!");
							
					alice_log.close();
					break;
			                
		            	}
		            	
		            }
		            
		            System.exit(0);

		        } catch(Exception e){

		            	// close connection. 
		        	dosDb.close(); 
		            	disDb.close();
		            	dbServer.close();
		        }
	        	
	        }
	        
		scan.close();
	        
		} catch (IOException e) {
			e.printStackTrace();
		} 

	}
	
	public static String getTimestamp(){
		return new SimpleDateFormat("dd.MM.yyyy HH:mm:ss").format(new Date());
	}
	
	public static String encrypt(String message) {		// encrypt message with public key of KDC
		
		byte[] encrypted_text = null;
		
		try {
			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(new FileInputStream("./cert/Kdc.cer"));
			PublicKey publicKey = certificate.getPublicKey();
		
			Cipher encrypt = Cipher.getInstance("RSA");
			encrypt.init(Cipher.ENCRYPT_MODE, publicKey);
			encrypted_text = encrypt.doFinal(message.getBytes());
			
		} catch (CertificateException | FileNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		} 
		
		return new String(Base64.getEncoder().encodeToString(encrypted_text));
	}

	public static String decrypt(String base64_p_a, Key key) {		// decrypt the P_A with the private key of Alice and get the session key
		
		String dec = null;
		
		try {
			byte[] p_a = Base64.getDecoder().decode(base64_p_a);
		
			Cipher decrypt = Cipher.getInstance("RSA");
			decrypt.init(Cipher.DECRYPT_MODE, key);
			String decrypted_text = new String(decrypt.doFinal(p_a));
			String ts = decrypted_text.split(",")[2];		// TS2
			dec = decrypted_text.split(",")[0] + "," + ts;		// K_A , TS2
			
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
		return dec;
		
	}

	private static PrivateKey getPrivateKey(String id){		// get the private key from txt file
		
		PrivateKey privkey = null;
		try {
			
			BufferedReader br = new BufferedReader(new FileReader("./keys/key" + id + ".txt"));
			String encoded_key = br.readLine();
			byte[] byte_key = Base64.getDecoder().decode(encoded_key);
			
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			privkey = keyfactory.generatePrivate(new PKCS8EncodedKeySpec(byte_key));
			
			br.close();
			
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.err.println("Error occured in :");
			e.printStackTrace();
		}
		return privkey;
		
	}

	public static String sesKeyEnc(String message, String key) {		// encrypt with session key
		
		String result = null;
		try{
			
			byte[] byte_session = Base64.getDecoder().decode(key);
			
			Key session = new SecretKeySpec(byte_session, 0, byte_session.length, "AES");
			
			Cipher encrypt = Cipher.getInstance("AES");
			encrypt.init(Cipher.ENCRYPT_MODE, session);
			byte[] encrypted_text = encrypt.doFinal(message.getBytes());
			result = Base64.getEncoder().encodeToString(encrypted_text);
		
		} catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
		return result;
	}

	public static String sesKeyDec(String message, String key) {		// decrypt with session key
		
		String result = null;
		try{
			
			byte[] byte_session = Base64.getDecoder().decode(key);
			byte[] byte_msg = Base64.getDecoder().decode(message);
			
			Key session = new SecretKeySpec(byte_session, 0, byte_session.length, "AES");
			
			Cipher decrypt = Cipher.getInstance("AES");
			decrypt.init(Cipher.DECRYPT_MODE, session);
			result = new String(decrypt.doFinal(byte_msg));
		
		} catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
		return result;
	}
}

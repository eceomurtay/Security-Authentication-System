import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class DBServer {

	public static void main(String[] args) {
		
		PrintStream database_log;
		
		try {
			
			database_log = new PrintStream(new FileOutputStream(new File("./Database_Log.txt"), true));
			
			ServerSocket dbSocket = new ServerSocket(3003);
			Socket client = dbSocket.accept();
			System.out.println("Alice connected.");
			
			// send data to client
			DataOutputStream dos = new DataOutputStream(client.getOutputStream());
			// read data from client
			DataInputStream dis = new DataInputStream(client.getInputStream());

			String session = null;
			
			while (true){
				
				try {
	                
	                if (dis.available() > 0){
	                	
	                	PrivateKey key = getPrivateKey("Database");
	                	String text = dis.readUTF();						// "Alice", Ticket, K_A(N1)
	                	
	                	if ((text.split(",")[0]).equals("step5")){
	                		
	                		String received = text.split(",")[1];		// K_A(N2 + 1)
	                		
	                		database_log.println(getTimestamp() + " Alice->Database : " + received);
	                		
	                		database_log.println(getTimestamp() + " \"Message Decrypted\" : " + sesKeyDec(received, session));
	                		database_log.println(getTimestamp() + " Database->Alice : " + "\"Authentication is completed!\"");
	                		
	                		System.out.println("- - - - - - - - - -");
	                		System.out.println("Authentication is completed!");
	                		
	                		break;
	                	}
	                	else {
		                	/*  Alice->Database : "Alice", Base64[Ticket], Base64[K_A(N_1)] */
		                	database_log.println(getTimestamp() + " Alice->Database : " + text);
		                	
		                	String dec = decrypt(text.split(",")[1], key);
		                	session = dec.split(",")[3];
		                	
		                	/* "Ticket Decrypted" : "Alice", "Database", [TS2], Base64[K_A]   */
		                	database_log.println(getTimestamp() + " \"Ticket Decrypted\" : " + dec);
	
		                	int nonce = Integer.parseInt(sesKeyDec(text.split(",")[2], session));		// decrypt with session key to get the nonce value
		                	
		                	/* "Message Decrypted" : N1=[N1] */
		                	database_log.println(getTimestamp() + " \"Message Decrypted\" : N1=" + Integer.toString(nonce) );
	
		                	SecureRandom random = new SecureRandom();
		        			int nonce2 = random.nextInt();
		                	
		        			String nonces = Integer.toString(nonce+1) + "," + Integer.toString(nonce2);	// N1+1, N2
		        			
		        			/* Database->Alice : [N1+1], [N2] */
		        			database_log.println(getTimestamp() + " Database->Alice : " + nonces);
		                	
		                	dos.writeUTF(sesKeyEnc(nonces, session));
		                	
		                	/* Database->Alice : Base64[K_A(N1+1, N2)] */
		                	database_log.println(getTimestamp() + " Database->Alice : " + sesKeyEnc(nonces, session));
		                }
	                }
	                
				} catch(Exception e){
					
					// close connection 
					dos.close(); 
	                dis.close(); 
					dbSocket.close();
					client.close();
				}
				
			}
			
			database_log.close();
			
			// Terminate the program
			System.exit(0);
			
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	public static String getTimestamp(){
		return new SimpleDateFormat("dd.MM.yyyy HH:mm:ss").format(new Date());
	}
	
	public static String decrypt(String base64_ticket, Key key) {		// decrypt the ticket
		
		String str = "";
		
		try {
			
			byte[] p_db = Base64.getDecoder().decode(base64_ticket);
		
			Cipher decrypt = Cipher.getInstance("RSA");
			decrypt.init(Cipher.DECRYPT_MODE, key);
			String decrypted_text = new String(decrypt.doFinal(p_db));
			
			if (decrypted_text.split(",")[1].equals("\"\"Database\"\""))			// verifies the correctness of ticket by looking at the id
				str = decrypted_text;					// Ticket = "Alice", "Database", TS2, K_A (=session key)
			
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
		return str;
		
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

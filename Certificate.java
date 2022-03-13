import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;

public class Certificate {

	private String[] cmdarray;
	
	public Certificate(String id) {			// keystore password = huceng
		
		if (id.equals("Kdc")){		// root
			
			cmdarray = new String[16];
			
			cmdarray[0] = "keytool";
			cmdarray[1] = "-genkeypair";
			cmdarray[2] = "-keysize";
			cmdarray[3] = "2048";
			cmdarray[4] = "-keyalg";
			cmdarray[5] = "RSA";
			cmdarray[6] = "-alias";
			cmdarray[7] = "keys" + id;
			cmdarray[8] = "-keystore";
			cmdarray[9] = "./keys" + id + ".jks";
			cmdarray[10] = "-dname";
			cmdarray[11] = "CN=Group24, OU=CS, O=Hacettepe University, L=Ankara, S=Ankara, C=TR";
			cmdarray[12] = "-storepass";
			cmdarray[13] = "huceng";
			cmdarray[14] = "-keypass";
			cmdarray[15] = "huceng";
			/*cmdarray[16] = "-ext";
			cmdarray[17] = "bc=ca:true";*/
		}
		
		else {
			
			cmdarray = new String[16];
			
			cmdarray[0] = "keytool";
			cmdarray[1] = "-genkeypair";
			cmdarray[2] = "-keysize";
			cmdarray[3] = "2048";
			cmdarray[4] = "-keyalg";
			cmdarray[5] = "RSA";
			cmdarray[6] = "-alias";
			cmdarray[7] = "keys" + id;
			cmdarray[8] = "-keystore";
			cmdarray[9] = "./keys" + id + ".jks";
			cmdarray[10] = "-dname";
			cmdarray[11] = "CN=Group24, OU=CS, O=Hacettepe University, L=Ankara, S=Ankara, C=TR";
			cmdarray[12] = "-storepass";
			cmdarray[13] = "huceng";
			cmdarray[14] = "-keypass";
			cmdarray[15] = "huceng";
		}
	}
	
	public void createCert(String id) {
		
		try {
			
			File certDirectory = new File("./cert/");
			if (!certDirectory.exists())
				certDirectory.mkdir();
			else{
				File certFile = new File("./cert/" + id + ".cer");
				if (certFile.exists()){
					System.out.println(id + ".cer" + " exists in cert directory!\n");
					return;
				}
			}
			
			String[] cmdarr = new String[10];
		
			cmdarr[0] = "keytool";
			cmdarr[1] = "-export";
			cmdarr[2] = "-keystore";
			cmdarr[3] = "keys" + id + ".jks";
			cmdarr[4] = "-alias";
			cmdarr[5] = "keys" + id;
			cmdarr[6] = "-file";
			cmdarr[7] = "./" + certDirectory + "/" + id + ".cer";
			cmdarr[8] = "-storepass";
			cmdarr[9] = "huceng";
		
			Process process = Runtime.getRuntime().exec(cmdarr);
			
			int exitVal = process.waitFor();
			
			if (exitVal == 0) {
				File oldCert = new File("./" + id + ".cer");
				oldCert.delete();
				System.out.println(id + " Certificate was created.\n");
			}
			
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
		
	}
	
	public void certSignRequest(String id){
		
	
		try {
				
			String[] cmdarr = new String[10];
			
			cmdarr[0] = "keytool";
			cmdarr[1] = "-certreq";
			cmdarr[2] = "-keystore";
			cmdarr[3] = "keys" + id + ".jks";
			cmdarr[4] = "-alias";
			cmdarr[5] = "keys" + id;
			cmdarr[6] = "-file";
			cmdarr[7] = "keys" + id + ".csr";
			cmdarr[8] = "-storepass";
			cmdarr[9] = "huceng";
			
			Process process = Runtime.getRuntime().exec(cmdarr);
			
			int exitVal = process.waitFor();
			
			/*if (exitVal == 0) {
				System.out.println(id + " requested.");
			}*/
			
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}

	}
	
	public void sign(String id){
		
		
		try {
				
			String[] arr = new String[12];
			
			arr[0] = "keytool";
			arr[1] = "-gencert";
			arr[2] = "-keystore";
			arr[3] = "keysKdc.jks";
			arr[4] = "-alias";
			arr[5] = "keysKdc";
			arr[6] = "-infile";
			arr[7] = "keys" + id + ".csr";
			arr[8] = "-outfile";
			arr[9] = id + ".cer";			// certificate
			arr[10] = "-storepass";
			arr[11] = "huceng";
			
			Process process = Runtime.getRuntime().exec(arr);
			
			int exitVal = process.waitFor();
			
			/*if (exitVal == 0) {
				System.out.println(id + " signed.");
			}*/
			
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}

	}
	
	public void createKeys(String id) {		// public & private key pairs and private key file is created
		
		try {
			
			File keyDirectory = new File("./keys/");	// check the existence of directory
			if (!keyDirectory.exists())
				keyDirectory.mkdir();
			else{
				File keyFile = new File("./keys/key" + id + ".txt");
				if (keyFile.exists()){
					System.out.println("key" + id + ".txt" + " exists in keys directory!");
					return;
				}
			}
			
			Process process = Runtime.getRuntime().exec(cmdarray);	
			int exitVal = process.waitFor();
			
			if (exitVal == 0) {
				//System.out.println(id + " Public & Private keys were created.");
			
				Key privateKey = getPrivateKey(id);
				byte[] byte_key = privateKey.getEncoded();
				String base64key = Base64.getEncoder().encodeToString(byte_key);
				
				BufferedWriter bw = new BufferedWriter(new FileWriter(new File("./" + keyDirectory + "/key" + id + ".txt")));
				bw.write(base64key);
				bw.close();
			}
			
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
		
	}
	
	private Key getPrivateKey(String id){
		
		Key privkey = null;
		try {
			
			char[] pwd = "huceng".toCharArray();
			KeyStore keystore = KeyStore.getInstance("JKS");
			keystore.load(new FileInputStream("./keys" + id + ".jks"), pwd);
			String alias = "keys" + id;
			privkey = keystore.getKey(alias, pwd);
			
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			System.err.println("Error occured in :");
			e.printStackTrace();
		}
		return privkey;
		
	}
	
	
}

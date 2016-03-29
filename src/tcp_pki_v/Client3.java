package tcp_pki_v;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
public class Client3 {
	private static String[] route = {"Client1", "Router2", "Client3"};
	private static List<PublicKey> publickeys;
	public static KeyPair generateKeyPair () throws NoSuchAlgorithmException {
		// Generate a key-pair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(512); // 512 is the keysize.
		KeyPair kp = kpg.generateKeyPair();
		return kp;
	}
	
	private static byte[] decrypt(byte[] inpBytes, PrivateKey key, String xform) throws Exception{
		Cipher cipher = Cipher.getInstance(xform);
	    cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	public static PublicKey getPublicKey(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException{
		ServerSocket publickKeySocket = new ServerSocket(portNumber);
		while(true){
			Socket connectionSocket = publickKeySocket.accept();
			BufferedReader inFromClient1 = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream())); 
			//DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
			//String clientSentence = inFromClient1.readLine();
			
			String pubk = inFromClient1.readLine(); 
			byte[] decodedPublicKey = Base64.getDecoder().decode(pubk);
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedPublicKey));
			return publicKey;
			//publickeys.add(publicKey);
			//System.out.println(publicKey.toString());
		}
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, UnknownHostException, IOException, InvalidKeySpecException {
		String xform = "RSA/ECB/PKCS1Padding";
 		KeyPair client3_kp = Client3.generateKeyPair();
 		PublicKey client1_publickey= Client3.getPublicKey(4444);
		System.out.println("reply from client1: " + client1_publickey.toString());
 		PublicKey router2_publickey= Client3.getPublicKey(4445);
		System.out.println("reply from router2: " + router2_publickey.toString());
 		
	}

}

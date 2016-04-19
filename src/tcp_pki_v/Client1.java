package tcp_pki_v;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import java.util.Base64;
import java.util.HashMap;

public class Client1 {
	private static String[] route = Planner.route;
	
	public static KeyPair generateKeyPair () throws NoSuchAlgorithmException {
		// Generate a key-pair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(512); // 512 is the keysize.
		KeyPair kp = kpg.generateKeyPair();
		return kp;
	}
	
	private static byte[] encrypt(byte[] inpBytes, PrivateKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	private static void sendPublickey(KeyPair kp, int portNumber) throws UnknownHostException, IOException{
		
		BufferedReader inFromClient1 = new BufferedReader( new InputStreamReader(System.in));
		Socket client1Socket = new Socket("localhost", portNumber);
		DataOutputStream outToClient3 = new DataOutputStream(client1Socket.getOutputStream());
		PublicKey pubk = kp.getPublic();
		String encoded = Base64.getEncoder().encodeToString(pubk.getEncoded());
		outToClient3.writeBytes(encoded + '\n');
		outToClient3.close();
	}
	
	private static void sendMsgToRouter2(KeyPair kp, int portNumber) throws Exception {
		String xform = "RSA/ECB/NoPadding";
		String msg;
		BufferedReader inFromClient = new BufferedReader( new InputStreamReader(System.in)); 
		msg = inFromClient.readLine();
		//String msg = "hello world";
		//MessageDigest hashedMsg = MessageDigest.getInstance("MD5"); 
		//hashedMsg.update(msg.getBytes(), 0, msg.length());
		//String hashedStringMsg = new BigInteger(1, hashedMsg.digest()).toString(64); 
		
		String original = msg;
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(original.getBytes());
		byte[] digest = md.digest();

		System.out.println("original:" + original);
		
		
		PrivateKey prvk = kp.getPrivate();
		
		Socket client1Socket = new Socket("localhost", portNumber);
		DataOutputStream outToRouter2 = new DataOutputStream(client1Socket.getOutputStream());
		byte[] encryptedMsg = encrypt(digest, prvk, xform);
		String encodedMsg = Base64.getEncoder().encodeToString(encryptedMsg);
		System.out.println("sending msg: " + encodedMsg);
		outToRouter2.writeBytes(encodedMsg + '\n');
		outToRouter2.close();
	}
	
 	public static void main(String[] args) throws Exception {
 		KeyPair client1_kp = Client1.generateKeyPair();
 		int publicKeySenderPort = 4444;
 		int msgPort = 6789;
 		Client1.sendPublickey(client1_kp, publicKeySenderPort);
 		Client1.sendMsgToRouter2(client1_kp, msgPort);
	}

}
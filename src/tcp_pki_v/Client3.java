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

import java.util.Arrays;
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
	
	private static byte[] decrypt(byte[] inpBytes, PublicKey key, String xform) throws Exception{
		Cipher cipher = Cipher.getInstance(xform);
	    cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	public static PublicKey getPublicKey(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException{
		ServerSocket publickKeySocket = new ServerSocket(portNumber);
		while(true){
			Socket connectionSocket = publickKeySocket.accept();
			BufferedReader inFromClient1OrRouter2 = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream())); 
			String pubk = inFromClient1OrRouter2.readLine(); 
			byte[] decodedPublicKey = Base64.getDecoder().decode(pubk);
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedPublicKey));
			return publicKey;
		}
	}
	
	private static byte[] readMsgFromRouter2(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException{
		ServerSocket router2MsgSocket = new ServerSocket(portNumber);
		while(true){
			Socket connectionSocket = router2MsgSocket.accept();
			BufferedReader inFromClient1 = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream())); 
			String msg = inFromClient1.readLine(); 
			byte[] decodedMsg = Base64.getDecoder().decode(msg);
			return decodedMsg;
		}
	}
	
	private static byte[] decryptMsg(byte[] encryptedMsg, PublicKey client1_publickey, PublicKey router2_publickey) throws Exception {
		String xform = "RSA/ECB/PKCS1Padding";
		byte[] decryptedRouter2 = Client3.decrypt(encryptedMsg, router2_publickey, xform);
		byte[] decryptedClient1 = Client3.decrypt(decryptedRouter2, client1_publickey, xform);
		return decryptedClient1;
	}
	
	
	public static void main(String[] args) throws Exception {
		String msg = "hello world";
		byte[] hashedMsg = MD5Hash.MD5Hash(msg);
 		KeyPair client3_kp = Client3.generateKeyPair();
 		int client1PubkPort = 4444;
 		int router2PubkPort = 4445;
 		int msgFromRouter2Port = 5678;
 		PublicKey client1_publickey= Client3.getPublicKey(client1PubkPort);
		System.out.println("reply from client1: " + client1_publickey.toString());
 		PublicKey router2_publickey= Client3.getPublicKey(router2PubkPort);
		System.out.println("reply from router2: " + router2_publickey.toString());
		byte[] msgFromRouter2 = Client3.readMsgFromRouter2(msgFromRouter2Port);
		byte[] decryptedMsg = Client3.decryptMsg(msgFromRouter2, client1_publickey, router2_publickey);
		System.out.println(Arrays.equals(decryptedMsg, hashedMsg));
	}

}

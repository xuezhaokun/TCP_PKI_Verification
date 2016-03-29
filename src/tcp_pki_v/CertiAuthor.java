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
public class CertiAuthor {
	private HashMap<String, KeyPair> keyPairs;
	
	public CertiAuthor() {
		this.keyPairs = new HashMap<String, KeyPair>();
	}

	public static CertiAuthor CA = new CertiAuthor();

	public HashMap<String, KeyPair> getKeyPairs() {
		return keyPairs;
	}

	public void setKeyPairs(HashMap<String, KeyPair> keyPairs) {
		this.keyPairs = keyPairs;
	}
	public static void main(String[] args) throws NoSuchAlgorithmException {
 		
 		for (Map.Entry<String, KeyPair> entry : CertiAuthor.CA.getKeyPairs().entrySet()) {
 		    System.out.println(entry.getKey());
 		}
 		
	}
	
}

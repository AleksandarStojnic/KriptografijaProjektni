import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class AsyCript {

	
	public static byte[] encrypt(byte[]input, PublicKey key) {
        byte[] encrypted = null;
        try {
         
          final Cipher cipher = Cipher.getInstance("RSA");
          
          // Enkripcija
          cipher.init(Cipher.ENCRYPT_MODE, key);
          encrypted = cipher.doFinal(input);
        } catch (Exception e) {
          e.printStackTrace();
        }
        return encrypted;
      }
	
	
	 public static byte[] decrypt(byte[] input, PrivateKey key) {
	        byte[] decrypted = null;
	        try {
	          
	          final Cipher cipher = Cipher.getInstance("RSA");

	          // Dekripcija sa privatnim kljucem
	          cipher.init(Cipher.DECRYPT_MODE, key);
	          decrypted = cipher.doFinal(input);

	        } catch (Exception ex) {
	          ex.printStackTrace();
	        }
          return decrypted;
	        
	      }
}

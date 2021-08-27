import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SymetricCript {

	
	public static byte[] symmetricEnkripcija(byte[] input,SecretKey kljuc, String algoritam) throws NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	byte output[] = null;
	Cipher cipher = Cipher.getInstance(algoritam);
	cipher.init(Cipher.ENCRYPT_MODE, kljuc);
	output = cipher.doFinal(input);
	return output;
}

public static byte[] symmetricDecrypt(byte[] input,SecretKey kljuc, String algoritam ) throws NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeyException {
	byte output[] = null;
	Cipher cipher = Cipher.getInstance(algoritam);
	cipher.init(Cipher.DECRYPT_MODE, kljuc);
	try {
		output = cipher.doFinal(input);
	} catch (BadPaddingException | IllegalBlockSizeException e) {
		return "error".getBytes();
	}
	return output;
}
}

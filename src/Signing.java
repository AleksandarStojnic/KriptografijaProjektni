import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;



public class Signing {

	
	public static void Sign(String algoritam, String pathFajla, String savePath, PrivateKey privateKey){
		
		try {
		// Instanciraj i inicijalizuj Signature
        Signature signature = Signature.getInstance(algoritam);
        signature.initSign(privateKey);
		
       //Trpamo bytove i koristimo update() da potpisemo
        byte[] bytes = Files.readAllBytes(Paths.get(pathFajla));
        signature.update(bytes);
        byte[] digitalSignature = signature.sign();
        
        // Sacuvamo 
        Files.write(Paths.get(savePath), digitalSignature);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}
	
	public static boolean Verify (String algoritam, String pathFajla, String pathPotpisa, PublicKey publicKey){
		 try {
		//Ucitamo bytove potpisa
         byte[] digitalSignature = Files.readAllBytes(Paths.get(pathPotpisa));

         //Inicijalizacija Signature klase
         Signature signature = Signature.getInstance(algoritam);
         signature.initVerify(publicKey);

         //Ucitavamo fajl koji treba verifikovati
         byte[] bytes = Files.readAllBytes(Paths.get(pathFajla));
         signature.update(bytes);

         //Provjeri potpis
         boolean verified = signature.verify(digitalSignature);
         return verified;
	}
		 catch (Exception e) {
				e.printStackTrace();
				return false;
			}
	}
	
}

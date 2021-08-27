import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class CertBuilder {
  
	private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	

	public CertBuilder() throws Exception
	{
		
		
		//Probacemo u konstruktoru napraviti certifikat al CA i to samo jednom
		
		Security.addProvider(new BouncyCastleProvider()); //Provajder
		
		//key pair generator
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
	    keyPairGenerator.initialize(2048);
        
        //Sad vrijeme setujemo pocetak na juce a kraj za godinu dana
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();
        
        //Prvo moramo napraviti root cert, znaci prvo keypair pa random serial pa certifikat 
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        
        // Od i Za root cert
        X500Name rootCertIssuer = new X500Name("CN=root-cert");
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        //Dodaj extenziju i basic constrain da bude root
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        // Kreiraj cert holder i exportuj
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);
        
        writeCertToFileBase64Encoded(rootCert, "root-cert.cer");
        exportKeyPairToKeystoreFile(rootKeyPair, rootCert, "root-cert", "root-cert.pfx", "PKCS12", "sigurnost");
	  
      //  rootCI=rootCertIssuer;
        

	}
	
	public static KeyStore loadKeyStore(final File keystoreFile,
		    final String password, final String keyStoreType)
		    throws KeyStoreException, IOException, NoSuchAlgorithmException,
		    CertificateException {
		  if (null == keystoreFile) {
		    throw new IllegalArgumentException("Keystore url may not be null");
		  }
		  final URI keystoreUri = keystoreFile.toURI();
		  final URL keystoreUrl = keystoreUri.toURL();
		  final KeyStore keystore = KeyStore.getInstance(keyStoreType);
		  InputStream is = null;
		  try {
		    is = keystoreUrl.openStream();
		    keystore.load(is, null == password ? null : password.toCharArray());
		 
		  } finally {
		    if (null != is) {
		      is.close();
		    }
		  }
		  return keystore;
		}
	
	public static KeyPair getKeyPair(final KeyStore keystore, 
		    final String alias, final String password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		  final Key key = (PrivateKey) keystore.getKey(alias, password.toCharArray());

		  final Certificate cert = keystore.getCertificate(alias);
		  final PublicKey publicKey = cert.getPublicKey();
          KeyPair kljucevi = new KeyPair(publicKey, (PrivateKey) key);
		  return kljucevi;
		}
	
	
	public static X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
	    X509Certificate certificate = null;
	    CertificateFactory cf = null;
	    try {
	        if (certificateString != null && !certificateString.trim().isEmpty()) {
	            certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----", "")
	                    .replace("-----END CERTIFICATE-----", ""); // NEED FOR PEM FORMAT CERT STRING
	            byte[] certificateData = Base64.decode(certificateString);
	            cf = CertificateFactory.getInstance("X509");
	            certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
	        }
	    } catch (CertificateException e) {
	        throw new CertificateException(e);
	    }
	    return certificate;
	}
	
	

	 static void noviCert (String name) throws Exception
	 {
		 //Mozda treba jos jedan provajder
		 Security.addProvider(new BouncyCastleProvider()); 
		 
		 
		 //Ovde cemo izvuci certifikat root
        String path=(System.getProperty("user.dir").toString()+"\\users\\" + name);
        X509Certificate rootCert = null;
        Path pathh = Paths.get(System.getProperty("user.dir").toString()+"\\root-cert.cer");
        String cert = Files.readString(pathh);
        rootCert = convertToX509Cert(cert); 
       
        //Ovde izvlacimo parkljuceva da pravimo nove certifikate
        File file = new File (System.getProperty("user.dir").toString()+"\\root-cert.pfx");
        KeyStore keystore = loadKeyStore(file,"sigurnost", "PKCS12");
        KeyPair kp = getKeyPair(keystore,"root-cert", "sigurnost");
        
        X500Name rootCertIssuer = new X500Name("CN=root-cert"); //ovo je pokusaj neki
       
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();
        
        
        //key pair generator
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
	    keyPairGenerator.initialize(2048);
        
        // Napravi novi keypair i potpisi
        // pomocu CSR (Certificate Signing Request)
        X500Name issuedCertSubject = new X500Name("CN=issued-cert");
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
        
        // Potpisi par kljuceva sa root kljucem
        ContentSigner csrContentSigner = csrBuilder.build(kp.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        // Koristi potpisane kljuceve i CSR da napravis zahtjev
        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

        // Dodaj ekstenzije
        // Koristi basicConstraints da kazes da ovo nije CA certifikat
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        
		// Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        // Add intended key usage extension if needed
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));
        
        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

        // Verify the issued cert signature against the root (issuer) cert
       // issuedCert.verify(rootCert.getPublicKey(), BC_PROVIDER);

        writeCertToFileBase64Encoded(issuedCert, path + "\\" + name + ".cer");
        exportKeyPairToKeystoreFile(issuedCertKeyPair, issuedCert, "issued-cert", path + "\\" + name + "issued-cert.pfx", "PKCS12", "sigurnost");
	 }
	
	 static void exportKeyPairToKeystoreFile(KeyPair keyPair, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
	        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
	        sslKeyStore.load(null, null);
	        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new Certificate[]{certificate});
	        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
	        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
	    }

	    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
	    	File file = new File(fileName);
	        FileOutputStream certificateOut = new FileOutputStream(file);
	        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
	        certificateOut.write(Base64.encode(certificate.getEncoded()));
	        certificateOut.write("-----END CERTIFICATE-----".getBytes());
	        certificateOut.close();
	    }
	    
	    static boolean verify (String path) throws CertificateException, IOException
	    {
	    	X509Certificate userCert = null;
	        Path pathh = Paths.get(path);
	        String cert = Files.readString(pathh);
	        userCert = convertToX509Cert(cert); 
	    	try {
	       userCert.checkValidity(); //dodaj ovde da probas jos u odnosu na javni kljuc rootca
	       return true;
	    } catch(Exception e)
	    	{
	    	  e.printStackTrace();
	    	  return false;
	    	}
	    }
	
}

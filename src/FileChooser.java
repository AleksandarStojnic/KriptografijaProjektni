import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileSystemView;

public class FileChooser extends JPanel implements ActionListener {

	private static final long serialVersionUID = 1L;
	
	public static final String SIMETRIC_ALGORITAM = "AES"; // AES, DES I Blowfish
	public static final String DIG_SIG_ALGORITAM = "SHA256withRSA"; // MD5withRSA,SHA1withRSA,SHA256withRSA
	
	    JButton openButton, createButton, uploadButton, downloadButton, deleteButton, sharedDir; //Ovde dodaj dugmad pa radi sa njima
	    JTextArea log;
	    JFileChooser fc;
	    String root;
	    String name;
	    KeyPair kp;
	    SecretKey key;
	    
	    
	    public FileChooser(String root, String name) throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException { //Ovde dodaj root folder da mozes kontrolisati ko sta moze raditi
			super(new BorderLayout());
			
			FileSystemView fsv = new DirectoryRestriction(new File(root)); //Ovo koristimo za ogranicimo korisnika
			                                                               //Valja provjeriti radi li ovo kurca
			this.name=name;
			this.root=root;
			
			log = new JTextArea(5,20);  //Inicijalizuj log
	        log.setMargin(new Insets(5,5,5,5));
	        log.setEditable(false);
	        JScrollPane logScrollPane = new JScrollPane(log);
	        
	        fc = new JFileChooser(fsv); //Novi file chooser
	        
	        //Definisi dugmad ovde
	        openButton= new JButton("Otvori");
	        openButton.addActionListener(this);
	        
	        createButton = new JButton("Kreiraj");
	        createButton.addActionListener(this);
	        
	        uploadButton = new JButton("Upload");
	        uploadButton.addActionListener(this);
	        
	        downloadButton = new JButton("Download");
	        downloadButton.addActionListener(this);
	        
	        deleteButton = new JButton("Delete");
	        deleteButton.addActionListener(this);
	        
	        sharedDir = new JButton("Djeljeni folder");
	        sharedDir.addActionListener(this);
	        
	        JPanel buttonPanel = new JPanel(); //Prakticno je dodati dugmad u odvojen panel fore radi
	        buttonPanel.add(openButton);
	        buttonPanel.add(createButton);
	        buttonPanel.add(uploadButton);
	        buttonPanel.add(downloadButton);
	        buttonPanel.add(deleteButton);
	        buttonPanel.add(sharedDir);
	        
	        add(buttonPanel, BorderLayout.PAGE_START);  //utrpaj ovo u panel
	        add(logScrollPane, BorderLayout.CENTER);
	        
	        getKeys(name);
		}
	    
	    


		@Override
		public void actionPerformed(ActionEvent e) { //Ovde cemo trpati dugme po dugme i njihovu funkcionalnost
			// TODO Auto-generated method stub
			
			if (e.getSource() == openButton) { //Otvaranje fajla u default programu
				int a = fc.showOpenDialog(null);

			    if (a == JFileChooser.APPROVE_OPTION) {
		
			      File fileToOpen = fc.getSelectedFile();
			      String nazivFajla = fileToOpen.getName();
			   
	 		     
	 		      File signatureFile = new File (root + "\\sig\\" + nazivFajla); 
	 		      if (signatureFile.exists()) //Ako postoji fajl provjeri jel valja potpis
	 		      {
	 		      if (Signing.Verify(DIG_SIG_ALGORITAM, fileToOpen.getAbsolutePath(), signatureFile.getAbsolutePath(), kp.getPublic()))
	 		      {
	 		    	 try {
						Desktop.getDesktop().open(fileToOpen);
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} 
	 		      }
	 		      else
	 		      {
	 		    	 JOptionPane.showMessageDialog(null, "KOMPRIMITOVANA DATOTEKA", "Pop up window ;)", JOptionPane.INFORMATION_MESSAGE);
	 		      }
	 		      }
	 		      else // Ako ne postoji onda potpisi jer ga otvaras prvi put
	 		      {
	 		    	Signing.Sign(DIG_SIG_ALGORITAM, fileToOpen.getAbsolutePath(), signatureFile.getAbsolutePath(), kp.getPrivate());  
	 		    	  
	 		      }
			    } 
			}
			
			else if (e.getSource() == createButton) { //Kreiranje i editovanje tekst fajlova
				CreateEditTxt editor = new CreateEditTxt(root, name, kp, DIG_SIG_ALGORITAM);
				editor.setVisible(true);
			}
			
			else if (e.getSource() == uploadButton) { //Upload na kriptovani folder
				int a = fc.showOpenDialog(null);

			    if (a == JFileChooser.APPROVE_OPTION) {
			    	
			     File fileToOpen = fc.getSelectedFile();
				 String nazivFajla = fileToOpen.getName();
				 String savePath = root + "\\enc\\" + nazivFajla;
				 byte [] dekriptovan = null; //Ovo ce nam biti byte array koji nije zakriptovan
				 byte [] enkriptovan = null; // Ovo ce nam biti byte array koji je zakriptovan
				 try {
					dekriptovan = Files.readAllBytes(fileToOpen.toPath());
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			       try {
			    	   //Ovde kriptujemo
				    enkriptovan = SymetricCript.symmetricEnkripcija(dekriptovan, key, SIMETRIC_ALGORITAM);
				} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
						| IllegalBlockSizeException | BadPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}	
			      //Ovde cemo zakriptovano trpati u fajl pa sacuvati
			      File zakriptovan = new File(savePath);
			      FileOutputStream outputStream;
				try {
					outputStream = new FileOutputStream(zakriptovan);
					outputStream.write(enkriptovan);
					outputStream.close();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			    
			    fileToOpen.delete();	
			    }
			}
			
			else if (e.getSource() == downloadButton) {
				int a = fc.showOpenDialog(null);

			    if (a == JFileChooser.APPROVE_OPTION) {
			    	
			     File fileToOpen = fc.getSelectedFile();
				 String nazivFajla = fileToOpen.getName();
				 String savePath = root + "\\dec\\" + nazivFajla;
				 byte [] dekriptovan = null; //Ovo ce nam biti byte array koji nije zakriptovan
				 byte [] enkriptovan = null; // Ovo ce nam biti byte array koji je zakriptovan
				 
				 try {
					 enkriptovan = Files.readAllBytes(fileToOpen.toPath());
					 dekriptovan = SymetricCript.symmetricDecrypt(enkriptovan, key, SIMETRIC_ALGORITAM);
					 File dekriptovanFajl = new File(savePath);
				     FileOutputStream outputStream;
				     outputStream = new FileOutputStream(dekriptovanFajl);
					 outputStream.write(dekriptovan);
					 outputStream.close();
				 }
				 catch (Exception e1) {
					 e1.printStackTrace();
				 }
				 
				 fileToOpen.delete();
			    }
			}
			
			else if (e.getSource() == deleteButton) {
				int a = fc.showOpenDialog(null);

			    if (a == JFileChooser.APPROVE_OPTION) {
			    	
			     File fileToOpen = fc.getSelectedFile();
			     String sigPath = root + "\\sig\\" + fileToOpen.getName();
			     File sigFile = new File(sigPath);
			     if (sigFile.exists())
			    	 sigFile.delete();
			     fileToOpen.delete();
			    }
			}
			
			else if (e.getSource() == sharedDir) {
				DijeljeniFolder window = new DijeljeniFolder(name, kp);
				window.setVisible(true);
				
			}
		}
		
		
		public void getKeys(String name) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
		
			//Par kljuceva
			String path=(System.getProperty("user.dir").toString()+"\\users\\" + name);
	        File file = new File (path + "\\" + name + "issued-cert.pfx");
	        KeyStore keystore = CertBuilder.loadKeyStore(file,"sigurnost", "PKCS12");
	        KeyPair kp = CertBuilder.getKeyPair(keystore,"issued-cert", "sigurnost");
	        this.kp=kp;
	        
	        
	        //Kljuc za simetricno kriptovanje
	        BufferedReader in = new BufferedReader(new FileReader(new File(path +"\\kljuc")));
	        String kljucString = in.readLine();
			in.close();
			byte[] decKey = kljucString.getBytes();
			key = new SecretKeySpec(decKey, SIMETRIC_ALGORITAM);
		
		}
		
		public static void createAndShowGUI(String root, String name) throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException { //ovo korisiti da pokrenes File Choosera
	        //Kreiraj
	        JFrame frame = new JFrame("FileChooser");
	        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	 
	        //Napuni prozor
	        frame.add(new FileChooser(root, name)); // Ovde pravimo prozor i pruzamo konstruktoru putanju roota
	 
	        //Prikazi prozor
	        frame.pack();
	        frame.setVisible(true);
	    }
}

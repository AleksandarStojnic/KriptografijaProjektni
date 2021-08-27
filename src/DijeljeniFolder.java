import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileSystemView;
import javax.swing.JTextField;

public class DijeljeniFolder extends JFrame implements ActionListener {

	private static final long serialVersionUID = 1L;
	JButton btnUpload, btnDownload;
	JTextArea korisnik;
    JFileChooser local, shared;
    String path= System.getProperty("user.dir").toString()+"\\shared";
    String name;
    String localPath;
    String root = System.getProperty("user.dir").toString()+"\\root\\";
    private JTextField textField;
    KeyPair mojPar;
	
    
    public DijeljeniFolder(String name, KeyPair kljuc)
    { 
    	
    	this.name=name;
	    mojPar=kljuc;
	    localPath = System.getProperty("user.dir").toString()+"\\root\\" + name;
	    
	    
    	getContentPane().setLayout(null);
    	FileSystemView fsv = new DirectoryRestriction(new File(path));
    	shared = new JFileChooser(fsv);
    	
    	FileSystemView fsv1 = new DirectoryRestriction(new File(localPath));
    	local = new JFileChooser(fsv1);
    	
    	
	     btnUpload = new JButton("Upload");
	     btnUpload.setBounds(52, 94, 89, 23);
	     getContentPane().add(btnUpload);
	     btnUpload.addActionListener(this);
	     
	     btnDownload = new JButton("Download");
	     btnDownload.setBounds(227, 94, 89, 23);
	     getContentPane().add(btnDownload);
	     btnDownload.addActionListener(this);
	     
	     textField = new JTextField();
	     textField.setBounds(144, 35, 96, 20);
	     getContentPane().add(textField);
	     textField.setColumns(10);
	     
	     
	     
    	
    }
	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		
		//Ovde bi trebao svoj fajl izabrati pa zakriptovati tudjim javnim pa staviti u folder
		if (e.getSource() == btnUpload){ 
			int a = local.showOpenDialog(null);

		    if (a == JFileChooser.APPROVE_OPTION) {
		    	
		    	File fileToOpen = local.getSelectedFile();
				String nazivFajla = fileToOpen.getName();
				String primaoc = textField.getText();
				File dirPrimaoca = new File (System.getProperty("user.dir").toString()+"\\users\\" + primaoc + "\\" + primaoc + "issued-cert.pfx");
				byte [] dekriptovan = null; 
				byte [] enkriptovan = null;
				
				PublicKey key;
				
				if (dirPrimaoca.exists()) {
					key = getKey(primaoc);
					try {
						
					dekriptovan = Files.readAllBytes(fileToOpen.toPath());
					enkriptovan = AsyCript.encrypt(dekriptovan, key);
					File enkriptovanFajl = new File(path + "\\" + nazivFajla);
				    FileOutputStream outputStream;
				    outputStream = new FileOutputStream(enkriptovanFajl);
					outputStream.write(enkriptovan);
					outputStream.flush();
					outputStream.close();
						
					}
					catch(Exception e1) {
						e1.printStackTrace();
					}
					
				}
				
				else {
					JOptionPane.showMessageDialog(null, "Korisnik nepostoji", "Pop up window ;)", JOptionPane.INFORMATION_MESSAGE);  
				}
		    }
		}
		
		//Ovde bi trebao uci u shared folder naci fajl otkriptovati svojim privatnim pa u folder metnuti
		else if (e.getSource() == btnDownload) {
			int a = shared.showOpenDialog(null);

		    if (a == JFileChooser.APPROVE_OPTION) {
		    	
		    	File fileToOpen = shared.getSelectedFile();
				String nazivFajla = fileToOpen.getName();
				byte [] dekriptovan = null;
				byte [] enkriptovan = null;
				
				try {
					 enkriptovan = Files.readAllBytes(fileToOpen.toPath());
					 dekriptovan = AsyCript.decrypt(enkriptovan, mojPar.getPrivate());
					 File dekriptovanFajl = new File(localPath + "\\dec\\" + nazivFajla);
				     FileOutputStream outputStream;
				     outputStream = new FileOutputStream(dekriptovanFajl);
					 outputStream.write(dekriptovan);
					 outputStream.close();
					
				}
				catch (Exception e1)
				{
					e1.printStackTrace();
				}
		    }
			
		}
		
	}
	
	public PublicKey getKey (String name) {
		
		String path=(System.getProperty("user.dir").toString()+"\\users\\" + name);
        File file = new File (path + "\\" + name + "issued-cert.pfx");
        KeyStore keystore = null;
		try {
			keystore = CertBuilder.loadKeyStore(file,"sigurnost", "PKCS12");
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        KeyPair kp = null;
		try {
			kp = CertBuilder.getKeyPair(keystore,"issued-cert", "sigurnost");
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        PublicKey key = kp.getPublic();
        return key;
	}
}

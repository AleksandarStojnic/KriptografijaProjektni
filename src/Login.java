import java.awt.EventQueue;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;




public class Login extends JFrame {

private static final long serialVersionUID = 1L;
	
	private JPanel contentPane;
	private JTextField textName;
	private JLabel lblPassword;
	private JPasswordField textPasswd;
	FileChooser filechooser;
	CertBuilder crtBuilder;  
	
	private ArrayList<String> users; // ovde cemo potrpati sve userse sto imamao u users folderu
	
	private String putanja = (System.getProperty("user.dir").toString()+"\\users"); //putanja do foldera users gdje se nalaze korisnici

	public Login() throws Exception {   //ovde kreiramo prozor i radimo login
		
		//crtBuilder = new CertBuilder(); // Ovo mi je samo trebalo da napravim root cert
		
		setResizable(false);
		setTitle("Fajl sistem");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setSize(520,540);
		setLocationRelativeTo(null);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		textName = new JTextField();
		textName.setFont(new Font("Tahoma", Font.BOLD, 14));
		textName.setBounds(182, 83, 150, 36);
		contentPane.add(textName);
		textName.setColumns(10);
		
		JLabel lblIme = new JLabel("Username:");
		lblIme.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblIme.setBounds(212, 39, 89, 36);
		contentPane.add(lblIme);
		
		lblPassword = new JLabel("Password:");
		lblPassword.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblPassword.setBounds(216, 156, 81, 27);
		contentPane.add(lblPassword);
		
		JLabel wrongPassLbl = new JLabel("");
		wrongPassLbl.setFont(new Font("Segoe UI Historic", Font.BOLD, 16));
		wrongPassLbl.setBounds(181, 245, 206, 37);
		contentPane.add(wrongPassLbl);
		
		textPasswd = new JPasswordField();
		textPasswd.setBounds(182, 196, 150, 36);
		contentPane.add(textPasswd);
		
		users = new ArrayList<String>();
		initUsers();
		
		JButton btnNewButton = new JButton("Login");
		btnNewButton.setBounds(208, 295, 97, 36);
		contentPane.add(btnNewButton);
		
		btnNewButton.addActionListener(new ActionListener() { //login button
			public void actionPerformed(ActionEvent e) {
				String name= textName.getText();
				if((users.contains(name)))
				{
					try {
						if(provjeriSifru()) {
							if(provjeriSertifikat())
								login(name);
							else 
								wrongPassLbl.setText("Neispravan sertifikat");
						}
						else {
							wrongPassLbl.setText("Wrong password");
						}
					} catch (NoSuchAlgorithmException | InvalidKeySpecException e1) {
						e1.printStackTrace();
					} catch (CertificateException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (UnrecoverableKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (KeyStoreException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
			}
		});
		
		JButton btnNewButton_1 = new JButton("Registracija");
		btnNewButton_1.setBounds(212, 370, 93, 36);
		contentPane.add(btnNewButton_1);
		btnNewButton_1.addActionListener(new ActionListener() {
			public void actionPerformed (ActionEvent e) {
				//OVDE IDE REGISTRACIJA
				try {
					registracija(textName.getText(), String.valueOf(textPasswd.getPassword())); //imamo ime i sifru 
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} 
			}
		});
		
		
	}

	void initUsers() //trpamo u users usere
	{
		File document = new File(putanja);
		File[] filesInDocument = document.listFiles();
		for(int i=0;i<filesInDocument.length;i++)
		{
			String user=filesInDocument[i].toString().substring(putanja.length()+1);
			users.add(user);
		}
	}

	boolean provjeriSifru() throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		String sifraOriginal=""; 
		String passwordTest=String.valueOf(textPasswd.getPassword());
	    String pomocnaPutanja = (putanja+"\\"+textName.getText()+"\\password.txt");
		sifraOriginal = IOFunkcije.procitajFile(new File(pomocnaPutanja));
		return PasswordService.validatePassword(passwordTest, sifraOriginal);
	}
	
	boolean provjeriSertifikat() throws CertificateException, IOException 
	{
		String ime =textName.getText();
		String sertPutanja = (System.getProperty("user.dir").toString()+"\\users\\"+ime+"\\"+ ime +".cer");
		return CertBuilder.verify(sertPutanja);
	}
	
	void registracija(String name, String passwd) throws Exception { //ovde bi trebali odraditi svu registraciju certifikat, hash passwords, privatni i javni kljuc
		
		String putanja = (System.getProperty("user.dir").toString()+"\\users\\" + name);
		File file = new File(putanja);
		file.mkdir(); //Pravimo direktorijum prvo
		
		File file1 = new File(System.getProperty("user.dir").toString()+"\\root\\" + name);
		file1.mkdir(); //Root direktorijum 
		
		File dec = new File (file1.getAbsoluteFile() + "\\dec");
		dec.mkdir();
		
		File enc = new File (file1.getAbsoluteFile() + "\\enc");
		enc.mkdir();
		
		File sig = new File (file1.getAbsoluteFile() + "\\sig");
		sig.mkdir();
		
		CertBuilder.noviCert(name);
		
		
		try {
            File statText = new File(putanja+"\\password.txt");
            FileOutputStream is = new FileOutputStream(statText);
            OutputStreamWriter osw = new OutputStreamWriter(is);    
            Writer w = new BufferedWriter(osw);
            String password=String.valueOf(textPasswd.getPassword());
            String passString = PasswordService.generateStorngPasswordHash(password);
            w.write(passString);
            w.close();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Problem writing to the file in inicijalizujUsera");
        }
		
		//Ovde pravimo kljuc za simetricno kriptovanje
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 256;
		keyGenerator.init(keyBitSize, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();
		File simetricniKljuc = new File(putanja+"\\kljuc");
		byte[] hex = secretKey.getEncoded();
		FileOutputStream outputStream = new FileOutputStream(simetricniKljuc);
		try {
			outputStream.write(hex);
			outputStream.close();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
	
	private void login(String name) throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		dispose(); //Zatvori login
		FileChooser.createAndShowGUI(System.getProperty("user.dir").toString() + "\\root\\" + name, name); //Otvori filechooser
	}
	
	public static void main(String[] args) { //Ovde cemo main da krece od logina logicno
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Login frame = new Login();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}



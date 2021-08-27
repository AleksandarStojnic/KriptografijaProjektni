import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class CreateEditTxt extends JFrame implements ActionListener {

	private static final long serialVersionUID = 1L;
	private JTextField textField;
	private JTextArea textArea;
	private JButton btnSave, btnNewButton;
	String root;
	String name;
	String algoritam;
	KeyPair kp;
	
	public CreateEditTxt (String root, String name, KeyPair kp, String algoritam) {
		getContentPane().setLayout(null);
		
		textField = new JTextField(); 
		textField.setBounds(81, 11, 351, 20);
		getContentPane().add(textField);
		textField.setColumns(10);
		
		textArea = new JTextArea();
		textArea.setBounds(35, 65, 457, 240);
		getContentPane().add(textArea);
		
	    btnSave = new JButton("Save");
		btnSave.setBounds(135, 329, 89, 23);
		getContentPane().add(btnSave);
		btnSave.addActionListener(this);
		
		btnNewButton = new JButton("Open");
		btnNewButton.setBounds(257, 329, 89, 23);
		getContentPane().add(btnNewButton);
		btnNewButton.addActionListener(this);
		
		this.root=root;
		this.name=name;
		this.kp=kp;
		this.algoritam=algoritam;
	}
	
	
	
	
	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		
		if (e.getSource()==btnSave) { //Ovde cemo odraditi za Save implementaciju
			
			String nazivFajla = textField.getText();
			String pathFajla = root + "\\dec\\" + nazivFajla +".txt";
			File file = new File (pathFajla);
			BufferedWriter fileOut = null;
			try {
				fileOut = new BufferedWriter(new FileWriter(file));
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		    try {
				textArea.write(fileOut);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		    //Ovde potpisemo fajl kad ga sacuvamo
		    String savePath = root + "\\sig\\" + nazivFajla + ".txt";
		    Signing.Sign(algoritam, pathFajla, savePath, kp.getPrivate());
		}
		
		 else if (e.getSource()==btnNewButton) { //Ovde za otvaranje datoteke za editovanje
			 
			 //Ovako cemo probati da ogranicimo izbor fajlova
			 JFileChooser j = new JFileChooser(root+"\\dec\\"); 
			 
			 int r = j.showOpenDialog(null);
		    	
		    	if (r==JFileChooser.APPROVE_OPTION)
		    	{
		    	    String sigpath = root + "\\sig\\" + j.getSelectedFile().getName();	
		    		File fi = new File(j.getSelectedFile().getAbsolutePath());
		    	 if (Signing.Verify(algoritam, fi.getAbsolutePath(), sigpath, kp.getPublic())) {
		    		textField.setText(j.getSelectedFile().getName());
		    		textField.setText(textField.getText().replace(".txt", ""));
		    		try {
		    			String s1 = "",sl="";
		    			FileReader fr = new FileReader(fi);
		    			BufferedReader br = new BufferedReader (fr);
		    			sl = br.readLine();
		    			
		    			while ((s1=br.readLine())!=null)
		    			{
		    				sl=sl+"\n"+s1;
		    			}
		    			textArea.setText(sl);
		    			br.close();
		    		}
		    		catch(Exception evt) {
		    			JOptionPane.showMessageDialog(textArea, evt.getMessage());
		    		}
		    	 }
		    	 else
		    	 {
		    		 //POP UP WINDOW
		    		 JOptionPane.showMessageDialog(null, "KOMPRIMITOVANA DATOTEKA", "Pop up window ;)", JOptionPane.INFORMATION_MESSAGE);
		 		     
		    	 }
		    	}
		 }
		
		}
	}



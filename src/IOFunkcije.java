

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class IOFunkcije {
	
	public static String procitajFile(File file)
	{
		StringBuilder procitanaPoruka=new StringBuilder();
		try {
			BufferedReader in = new BufferedReader(new FileReader(file));
			String temp;
			try {
				while((temp=in.readLine()) != null)
				{
					procitanaPoruka.append(temp).append("\n");
				}
			}
			finally {
				in.close();
			}
		} catch (IOException e) {
			System.out.println("greska kod citanja poruke");
			e.printStackTrace();
		}
		return procitanaPoruka.toString();
	}
}

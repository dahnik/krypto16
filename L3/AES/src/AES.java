import java.io.BufferedOutputStream;
import java.io.Console;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AES {
	
	public static void main(String[] args) throws IOException
	{
		/*if(args[0]!="CBC"&&args[0]!="OFB"&&args[0]!="CFB"&&args[0]!="CTR")){
			System.out.println("CBC/OFB/CFB/CTR"); 
			return;
		}*/
		String tcipher = "AES/"+args[0]+"/PKCS5PAdding";//"CBC" ECB OFB CFB CTR;
		if(args[1]!="./keys.keystore") args[1]="./keys.keystore";
		if(args[2]!="zad3") args[2]="zad3";
		String alias=args[2];
		Security.addProvider(new BouncyCastleProvider());
		Console cons = System.console();
		//cons=System.console();
		//pass=123456
		System.out.println("Please enter the pass to keystore");
		//char[] pass= cons.readPassword();
		char[] pass = {'1','2','3','4','5','6'};
		System.out.println("Please enter path to file which u want to encrypt");
		Scanner input = new Scanner(System.in);
		String path1 = input.nextLine();
		try 
		{
			Cipher cipher = Cipher.getInstance(tcipher);
			KeyStore ks = KeyStore.getInstance("BKS");
			java.io.FileInputStream fIS = new java.io.FileInputStream(args[1]);
			ks.load(fIS, pass);
			FileInputStream f = new FileInputStream(path1);
		    byte[] everything = new byte[f.available()];
			f.read(everything);
			f.close();
			
		    String plik1 = "/home/dahn/Pulpit/zaszyfrowany.txt";
		    String plik2 = "/home/dahn/Pulpit/odszyfrowany.txt";
		        
		    byte[] iv1 = new byte[16];
			cipher.init(Cipher.ENCRYPT_MODE, ks.getKey(alias, pass), new IvParameterSpec(iv1));
			byte[] zaszyfrowane = (cipher.doFinal(everything));
			//System.out.println(new String (zaszyfrowane));
			try {
				FileOutputStream fop = new FileOutputStream(new File(plik1));
				fop.write(zaszyfrowane);
				fop.close();
			} catch (Exception e) {
				e.printStackTrace();
			} 
			FileInputStream fip = new FileInputStream(new File(plik1));
			byte[] everything1 = new byte[fip.available()];
			fip.read(everything1);
			fip.close();
			byte[] rozszyfrowane = null;
			byte[] iv = new byte[16];
			
			cipher = Cipher.getInstance(tcipher,"BC");
				
			cipher.init(Cipher.DECRYPT_MODE, ks.getKey(alias, pass),new IvParameterSpec(iv));
			rozszyfrowane = cipher.doFinal(everything1);	
			DataOutputStream ros = new DataOutputStream(new BufferedOutputStream (new FileOutputStream(plik2)));
			//System.out.println(new String (rozszyfrowane));
			ros.write(rozszyfrowane);
			ros.close();
			try {
				FileOutputStream fop = new FileOutputStream(new File(plik2));
				fop.write(rozszyfrowane);
				fop.close();
			} catch (Exception e) {
				e.printStackTrace();
			} 
			} catch (Exception e) {
			System.out.println("Catched");
			e.printStackTrace();
			} 

	}
}

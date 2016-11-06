
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javazoom.jl.decoder.InputStreamSource;
import javazoom.jl.player.Player;

public class MP5 {
	
	private static String config_path = "/home/dahn/Pulpit/Odtwarzacz/config.txt";
	private static String config = "/home/dahn/Pulpit/Odtwarzacz/decrypted /home/dahn/Pulpit/Odtwarzacz/keys.keystore zad3";
	private static String Esong = "/home/dahn/Pulpit/Odtwarzacz/encrypted";
	private static String song = "/home/dahn/Pulpit/Odtwarzacz/Mozart - Presto.mp3";
	private static char[] password = {'1', '2', '3', '4','5','6'};
	private static byte[] iv = new byte[16];
	private static int length=0;
	
	public static void main(String[] args) throws IOException
	{
		Security.addProvider(new BouncyCastleProvider());
    	
		try 
		{
			
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding","BC");
			
			SecretKey key1 = create_config();
			String[] tab = decrypt_file(key1);
			String Dsong = tab[0];
			tab[1]="/home/dahn/Pulpit/Odtwarzacz/keys.keystore";
			java.io.FileInputStream keystore = new java.io.FileInputStream(tab[1]); 
			String alias = tab[2];
			
			KeyStore ks = KeyStore.getInstance("BKS");
			ks.load(keystore, password);			
			FileInputStream fip = new FileInputStream(new File(song));
			byte[] everything = new byte[fip.available()];
			fip.read(everything);
			fip.close();
			
			cipher.init(Cipher.ENCRYPT_MODE, ks.getKey(alias, password), new IvParameterSpec(iv));
			byte[] zaszyfrowane = (cipher.doFinal(everything));
			
			try {
				FileOutputStream fop = new FileOutputStream(new File(Esong));
				fop.write(zaszyfrowane);
				fop.close();
			} catch (Exception e) {
				e.printStackTrace();
			} 
			//System.out.println(new String(everything));
				
			
			
			FileInputStream Efip = new FileInputStream(new File(Esong));
			byte[] everything1 = new byte[Efip.available()];
			Efip.read(everything1);
			Efip.close();
			
				
			
			byte[] rozszyfrowane = null;
			
			cipher = Cipher.getInstance("AES/CTR/NoPadding","BC");
				
			cipher.init(Cipher.DECRYPT_MODE, ks.getKey(alias, password),new IvParameterSpec(iv));
			rozszyfrowane = cipher.doFinal(everything1);	
			
			/*DataOutputStream ros = new DataOutputStream(new BufferedOutputStream (new FileOutputStream(Dsong)));
			ros.write(rozszyfrowane);
			ros.close();*/
			
			InputStream myInputStream = new ByteArrayInputStream(rozszyfrowane);
			//System.out.println(myInputStream);
	        Player player = new Player(myInputStream);
	        player.play();
			
			
			} catch (Exception e) {
			System.out.println("YYY masz błęda!");
			e.printStackTrace();
			} 
	}
	private String filename;
    private Player player; 


    public MP5(String filename) 
    {
        this.filename = filename;
    }

    public void close() 
    { 
    	if (player != null)
    		player.close();
    }

  
    public void play() 
    {
        try {
            FileInputStream fis = new FileInputStream(filename);
            BufferedInputStream bis = new BufferedInputStream(fis);
            player = new Player(bis);
        }
        catch (Exception e) 
        {
            System.out.println("Problem playing file " + filename);
            System.out.println(e);
        }

        
        // run in new thread to play in background
        new Thread() 
        {
            public void run()
            {
                try 
                {
                	player.play(); 
                }
                catch (Exception e) { System.out.println("Nie ma bata!" + e); }
            }
        }.start();

    }
    public static SecretKey create_config()
    {
    	SecretKey key1 = null;
    	KeyGenerator keygen1;
		try {
			keygen1 = KeyGenerator.getInstance("AES");
			SecureRandom random1 = new SecureRandom();
			keygen1.init(128, random1);
			key1 = keygen1.generateKey();
			
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding","BC");
			cipher.init(Cipher.ENCRYPT_MODE, key1, new IvParameterSpec(iv));
			
			byte[] Config = cipher.doFinal(config.getBytes());
			
			
			FileOutputStream fop = new FileOutputStream(new File(config_path));
			fop.write(Config);
			fop.close();
			
			} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//System.out.println(key1);
		return key1;
    }
    public static String[] decrypt_file(SecretKey key1)
    {
    	FileInputStream Efip;
    	String[] tab = new String[3];
		try {
			Efip = new FileInputStream(new File(config_path));
			byte[] everything1 = new byte[Efip.available()];
			Efip.read(everything1);
			Efip.close();
			String test=new String(everything1);
			length=test.length();
			//System.out.println(length);
				
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding","BC");
			cipher.init(Cipher.DECRYPT_MODE, key1, new IvParameterSpec(iv));
			byte[] rozszyfrowane = cipher.doFinal(everything1);	
			//System.out.println(new String (rozszyfrowane));
			String tekst = new String (rozszyfrowane);
			//System.out.println(tekst);
			int poczatek = 0;
			int j = 0;
			for(int i = 0; i < tekst.length(); i++)
			{
				if(tekst.charAt(i) == 32 || i == tekst.length()-1)
				{
					tab[j] = (tekst.substring(poczatek, i+1));
					j++;
					poczatek = i+1;
				}
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return tab;
    }
}
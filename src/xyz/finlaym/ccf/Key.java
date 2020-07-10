package xyz.finlaym.ccf;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.SecretKey;

import xyz.finlaym.crypto.ASymmetric;
import xyz.finlaym.crypto.BASE64;
import xyz.finlaym.crypto.Symmetric;

public class Key {
	private PublicKey pub;
	private PrivateKey priv;
	public Key(PublicKey pub, PrivateKey priv) {
		this.pub = pub;
		this.priv = priv;
	}
	
	public PublicKey getPub() {
		return pub;
	}

	public PrivateKey getPriv() {
		return priv;
	}
	public void writeToFile(File f) throws Exception{
		f.delete();
		f.createNewFile();
		
		PrintWriter out = new PrintWriter(new FileWriter(f,true));
		
		out.println("----key-1---");
		String key = BASE64.encode(pub.getEncoded());
		out.println("pub:"+pub.getAlgorithm()+":"+(count(key,"\n")+1));
		key = BASE64.encode(priv.getEncoded());
		out.println("priv:"+priv.getAlgorithm()+":"+(count(key,"\n")+1));
		out.println("---end--key---");
		
		out.close();
	}
	public void writeToFile(File f, SecretKey encKey) throws Exception{
		f.delete();
		f.createNewFile();
		
		PrintWriter out = new PrintWriter(new FileWriter(f,true));
		
		out.println("----enc-key-1---");
		String key = BASE64.encode(pub.getEncoded());
		out.println("pub:"+pub.getAlgorithm()+":"+(count(key,"\n")+1));
		key = BASE64.encode(Symmetric.encryptB(priv.getEncoded(),encKey,encKey.getAlgorithm()));
		out.println("priv:"+encKey.getAlgorithm()+":"+priv.getAlgorithm()+":"+(count(key,"\n")+1));
		out.println("---end--key---");
		
		out.close();
	}
	private static int count(String s1, String s2) {
		return s1.length()-s1.replaceAll(s2, "").length();
	}

	public static Key readKey(File f) throws Exception{
		Scanner in = new Scanner(f);
		boolean start = false;
		PublicKey pub = null;
		PrivateKey priv = null;
		while(in.hasNextLine()) {
			String s = in.nextLine();
			if(!start && !s.equals("----key-1---"))
				continue;
			if(!start && s.equals("----key-1---")) {
				start = true;
				continue;
			}
			if(s.equals("---end--key---"))
				break;
			String[] parse = s.split(":",2);
			switch(parse[0]) {
			case "pub":
				String[] split = parse[1].split(":",3);
				String algo = split[0];
				int numLines = Integer.valueOf(split[1]);
				String key = split[2];
				for(int i = 1; i < numLines; i++) {
					key += "\n"+in.nextLine();
				}
				pub = ASymmetric.getPublicKeyFromByteArray(BASE64.decode(key), algo);
				break;
			case "priv":
				split = parse[1].split(":",3);
				algo = split[0];
				numLines = Integer.valueOf(split[1]);
				key = split[2];
				for(int i = 1; i < numLines; i++) {
					key += "\n"+in.nextLine();
				}
				priv = ASymmetric.getPrivateKeyFromByteArray(BASE64.decode(key), algo);
				break;
			}
		}
		in.close();
		if(pub == null)
			throw new Exception("Public key cannot be null!");
		if(priv == null)
			throw new Exception("Private key cannot be null!");
		return new Key(pub,priv);
	}
	public static Key readKey(File f, SecretKey encKey) throws Exception{
		Scanner in = new Scanner(f);
		boolean start = false;
		PublicKey pub = null;
		PrivateKey priv = null;
		while(in.hasNextLine()) {
			String s = in.nextLine();
			if(!start && !s.equals("----enc-key-1---"))
				continue;
			if(!start && s.equals("----enc-key-1---")) {
				start = true;
				continue;
			}
			if(s.equals("---end--key---"))
				break;
			String[] parse = s.split(":",2);
			switch(parse[0]) {
			case "pub":
				String[] split = parse[1].split(":",3);
				String algo = split[0];
				int numLines = Integer.valueOf(split[1]);
				String key = split[2];
				for(int i = 1; i < numLines; i++) {
					key += "\n"+in.nextLine();
				}
				pub = ASymmetric.getPublicKeyFromByteArray(BASE64.decode(key), algo);
				break;
			case "priv":
				split = parse[1].split(":",4);
				String sAlgo = split[0];
				algo = split[1];
				numLines = Integer.valueOf(split[2]);
				key = split[3];
				for(int i = 1; i < numLines; i++) {
					key += "\n"+in.nextLine();
				}
				key = Symmetric.decrypt(key, encKey, sAlgo);
				priv = ASymmetric.getPrivateKeyFromByteArray(BASE64.decode(key), algo);
				break;
			}
		}
		in.close();
		if(pub == null)
			throw new Exception("Public key cannot be null!");
		if(priv == null)
			throw new Exception("Private key cannot be null!");
		return new Key(pub,priv);
	}
}

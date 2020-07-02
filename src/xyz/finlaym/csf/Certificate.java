package xyz.finlaym.csf;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import xyz.finlaym.crypto.ASymmetric;
import xyz.finlaym.crypto.BASE64;
import xyz.finlaym.crypto.HashingUtils;

public class Certificate {
	private PublicKey pub;
	private String[] flags;
	private Map<String,String> data;
	private String hash;
	private PublicKey signer;
	public Certificate(PublicKey pub, String[] flags,
			Map<String, String> data, String hash, PublicKey signer) {
		this.pub = pub;
		this.flags = flags;
		this.data = data;
		this.hash = hash;
		this.signer = signer;
	}
	public boolean verify() throws Exception{
		String cert = "---csf-cert-1---\n";
		String key = BASE64.encode(pub.getEncoded());
		cert += "pub:"+pub.getAlgorithm()+":"+(count(key,"\n")+1)+"\n";
		if(flags.length != 0)
			cert += "flags:"+concat(flags,":")+"\n";
		for(String s : data.keySet()) {
			cert += s+":"+data.get(s)+"\n";
		}
		
		String[] parse = hash.split(":",3);
		String hAlgo = parse[0];
		String sHash = parse[2];
		
		String actualHash = HashingUtils.hash(cert, hAlgo);
		String signedHash = ASymmetric.getSigned(sHash, signer, signer.getAlgorithm());
		return actualHash.equals(signedHash);
	}
	
	public PublicKey getPub() {
		return pub;
	}

	public String[] getFlags() {
		return flags;
	}

	public Map<String, String> getData() {
		return data;
	}

	public String getHash() {
		return hash;
	}

	public PublicKey getSigner() {
		return signer;
	}

	public void writeToFile(File f) throws Exception{
		f.delete();
		f.createNewFile();
		
		PrintWriter out = new PrintWriter(new FileWriter(f,true));
		
		out.println("---csf-cert-1---");
		String key = BASE64.encode(pub.getEncoded());
		out.println("pub:"+pub.getAlgorithm()+":"+(count(key,"\n")+1));
		if(flags.length != 0)
			out.println("flags:"+concat(flags,":"));
		for(String s : data.keySet()) {
			out.println(s+":"+data.get(s));
		}
		out.println("hash:"+hash);
		key = BASE64.encode(signer.getEncoded());
		out.println("signer:"+signer.getAlgorithm()+":"+(count(key,"\n")+1));
		
		out.close();
	}
	private static int count(String s1, String s2) {
		return s1.length()-s1.replaceAll(s2, "").length();
	}
	private static String concat(String[] s1, String s2) {
		if(s1.length == 0)
			return "";
		String s3 = "";
		for(String s : s1) {
			s3 += s2+s;
		}
		return s3.substring(s2.length());
	}
	public static Certificate readCertificate(File certificate) throws Exception{
		Scanner in = new Scanner(certificate);
		PublicKey pub = null;
		String[] flags = null;
		Map<String,String> data = new HashMap<String,String>();
		String hash = null;
		PublicKey signer = null;
		boolean start = false;
		while(in.hasNextLine()) {
			String s = in.nextLine();
			if(!start && !s.equals("---csf-cert-1---"))
				continue;
			if(!start && s.equals("---csf-cert-1---")) {
				start = true;
				continue;
			}
			if(s.equals("---end-csf-cert---"))
				break;
			String[] parse = s.split(":",2);
			switch(parse[0]) {
			case "pub":
				String[] split = parse[1].split(":");
				String algo = split[0];
				int numLines = Integer.valueOf(split[1]);
				String key = split[2];
				for(int i = 1; i < numLines; i++) {
					key += "\n"+in.nextLine();
				}
				pub = ASymmetric.getPublicKeyFromByteArray(BASE64.decode(key), algo);
				break;
			case "flags":
				flags = parse[1].split(",");
				break;
			case "hash":
				hash = parse[1];
				numLines = Integer.valueOf(parse[1].split(":")[1]);
				for(int i = 1; i < numLines; i++) {
					hash += "\n"+in.nextLine();
				}
				break;
			case "signer":
				split = parse[1].split(":");
				algo = split[0];
				numLines = Integer.valueOf(split[1]);
				key = split[2];
				for(int i = 1; i < numLines; i++) {
					key += "\n"+in.nextLine();
				}
				signer = ASymmetric.getPublicKeyFromByteArray(BASE64.decode(key), algo);
				break;
			default:
				data.put(parse[0], parse[1]);
				break;
			}
		}
		in.close();
		if(flags == null)
			flags = new String[0];
		if(pub == null)
			throw new Exception("Certificate public key cannot be null!");
		if(hash == null)
			throw new Exception("Certificate hash cannot be null!");
		if(signer == null)
			throw new Exception("Certificate signer cannot be null!");
		return new Certificate(pub, flags, data, hash, signer);
	}
}

package xyz.finlaym.csf;

import java.io.File;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import xyz.finlaym.crypto.ASymmetric;
import xyz.finlaym.crypto.BASE64;

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

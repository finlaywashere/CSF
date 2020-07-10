package xyz.finlaym.ccf;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class CertificateChain {
	private List<Certificate> certificates;

	public CertificateChain(List<Certificate> certificates) {
		this.certificates = certificates;
	}
	
	public List<Certificate> getCertificates() {
		return certificates;
	}
	public void writeToFile(File f) throws Exception{
		f.delete();
		f.createNewFile();
		
		PrintWriter out = new PrintWriter(new FileWriter(f,true));
		out.println("----cert-chain---");
		out.close();
		for(Certificate c : certificates) {
			c.writeToFile(f, true);
		}
		out = new PrintWriter(new FileWriter(f,true));
		out.println("---end--cert-chain---");
		out.close();
	}

	public static CertificateChain readFromFile(File f) throws Exception{
		Scanner in = new Scanner(f);
		boolean start = false;
		List<Certificate> certificates = new ArrayList<Certificate>();
		while(in.hasNextLine()) {
			String s = in.nextLine();
			if(!start && !s.equals("----cert-chain---"))
				continue;
			if(!start && s.equals("----cert-chain---")) {
				start = true;
				continue;
			}
			if(s.equals("---end--cert-chain---"))
				break;
			if(s.equals("----cert-1---")) {
				List<String> cert = new ArrayList<String>();
				cert.add(s);
				while(in.hasNextLine()) {
					s = in.nextLine();
					cert.add(s);
					if(s.equals("---end--cert---"))
						break;
				}
				certificates.add(Certificate.readCertificate(cert));
			}
		}
		in.close();
		return new CertificateChain(certificates);
	}
}


import java.security.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.security.spec.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Iterator;
import java.util.*;

public class JKSModifier  {

    private static InputStream fullStream ( String fname ) throws IOException {
        FileInputStream fis = new FileInputStream(fname);
        DataInputStream dis = new DataInputStream(fis);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return bais;
    }
	
	private static Map<String, String> listAlias(KeyStore keystore){
		Map<String, String> aliasMap = new HashMap<String, String>();
		
		try{
			Enumeration<String> aliases = keystore.aliases();
			while(aliases.hasMoreElements()){
				String alias = aliases.nextElement();
				Certificate certificate = keystore.getCertificate(alias);
				aliasMap.put(alias, certificate.toString());      
			}
		} catch(Exception e){
			e.printStackTrace();
		}
		return aliasMap;
	}
        
	
    public static void main ( String args[]) {
        String keyfile = "";
		String certfile = "";
		String alias = "";
		String keystorename = "";
		String keypass = "";
		String reset = "";
        
		if(args.length < 5 || args.length > 6){
			System.out.println("Usage: java ImportKey [keyfile] [certfile] [alias] [keystore] [keypass] reset(optional)");	
			System.exit(0);
		} else {
			keyfile = args[0];
			certfile = args[1];
			alias = args[2];
			keystorename = args[3];
			keypass = args[4];
			if(args.length == 6)
				reset = args[5];
			
			System.out.println("KeyFile:"+ keyfile+" CertFile:"+ certfile+" Alias:"+ alias+" KeyStore:"+ keystorename+" KeyPass:"+keypass+" Will be reset?"+(reset.equals("reset")));
		}
		
        try {
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            ks.load( null , keypass.toCharArray());
			
			if("reset".equals(reset)){
				System.out.println("Keystore is resetting...");
				ks.store(new FileOutputStream (keystorename), keypass.toCharArray());
				System.out.println("Keystore was reset successfully.");
			}

            ks.load(new FileInputStream (keystorename), keypass.toCharArray());
			
			Map<String, String> aliasMap = listAlias(ks);
			System.out.println("\nExisting alias are listing...");
			for(String aliasName:aliasMap.keySet()){
				System.out.println("AliasName:"+ aliasName);	
			}
			
			if(aliasMap.get(alias) != null){
				System.out.println("\n"+alias+" already exists in the keystore");
				System.exit(0);
			}
			
			System.out.println("");

            // loading Key
            InputStream fl = fullStream (keyfile);
            byte[] key = new byte[fl.available()];
            KeyFactory kf = KeyFactory.getInstance("RSA");
            fl.read ( key, 0, fl.available() );
            fl.close();
            PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec ( key );
            PrivateKey ff = kf.generatePrivate (keysp);

            // loading CertificateChain
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream certstream = fullStream (certfile);

            Collection c = cf.generateCertificates(certstream) ;
            Certificate[] certs = new Certificate[c.toArray().length];

            if (c.size() == 1) {
                certstream = fullStream (certfile);
                System.out.println("One certificate, no chain.");
                Certificate cert = cf.generateCertificate(certstream) ;
                certs[0] = cert;
            } else {
                System.out.println("Certificate chain length: "+c.size());
                certs = (Certificate[])c.toArray();
            }

            // storing keystore
            ks.setKeyEntry(alias, ff, 
                           keypass.toCharArray(),
                           certs );
            System.out.println ("Key and certificate stored.");
            System.out.println ("Alias:"+alias+"  Password:"+keypass);
            ks.store(new FileOutputStream ( keystorename ), keypass.toCharArray());
			aliasMap = listAlias(ks);
			System.out.println("\nEntries are listing...");
			for(String aliasName:aliasMap.keySet()){
				System.out.println("AliasName:"+ aliasName);	
			}
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}// KeyStore

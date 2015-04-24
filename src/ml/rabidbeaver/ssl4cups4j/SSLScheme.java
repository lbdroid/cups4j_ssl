package ml.rabidbeaver.ssl4cups4j;

import java.io.FileInputStream;
import java.security.KeyStore;

import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;

import android.content.Context;

public class SSLScheme {
	
	public static final String trustfile = "cupsprint-trustfile";
	public static final String password = "i6:[(mW*xh~=Ni;S|?8lz8eZ;!SU(S";

    public static Scheme getScheme(Context context){
        
    	FileInputStream fis = null;
    	Scheme scheme;
    	
        try {	
       		KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
 
           	try {
           		fis = context.openFileInput(trustfile);
           		trustStore.load(fis, password.toCharArray());
           	}
            catch (Exception e){
            	trustStore.load(null, null);
            }
           
            SSLSocketFactory sf = new AdditionalKeyStoresSSLSocketFactory(trustStore);
        	sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
           	scheme = new Scheme("https", sf, 443);
        }
        catch (Exception e){
        	scheme = getDefaultScheme();
        }
        finally {
            if (fis != null) {
            	try {
            		fis.close();
            	}catch (Exception e1){}
            }
        }
        return scheme;
    }
    
    private static Scheme getDefaultScheme(){
    	SSLSocketFactory sf = SSLSocketFactory.getSocketFactory();
    	sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
    	return new Scheme("https", sf, 443);
    }
    
}

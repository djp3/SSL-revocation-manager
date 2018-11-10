package net.djp3.sslcert.crl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;

import net.djp3.sslcert.CertificateVerificationException;

public class X509CRLWrapper implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 6399203416305063378L;
	private X509CRL data;

	public X509CRLWrapper(X509CRL data) {
		this.data = data;
	}
	
	public X509CRL getX509CRL() {
		return this.data;
	}
	
	private void readObject( ObjectInputStream objectinputStream ) throws ClassNotFoundException, IOException {
		try {
			//Read in DER format
			byte[] incoming = (byte[]) objectinputStream.readObject();
			//Wrap in an Input Stream
			InputStream targetStream = new ByteArrayInputStream(incoming);
			this.data = CRLVerifier.extractX509CRLFromStream(targetStream);
		} catch (ClassCastException e) {
			System.out.println("classcastexception");
		} catch (CertificateVerificationException e) {
			throw new IOException(e);
		}
	  }

	private void writeObject( ObjectOutputStream outputStream ) throws IOException {
		try {
			//Convert to DER format
			byte[] encoded = data.getEncoded();
			outputStream.writeObject(encoded);
		} catch (CRLException e) {
			throw new IOException(e);
		}
		finally {
			outputStream.flush();
		}
    }

}

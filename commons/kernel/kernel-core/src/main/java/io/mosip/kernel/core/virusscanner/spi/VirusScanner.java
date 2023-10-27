/**
 * 
 * 
 */
package io.mosip.kernel.core.virusscanner.spi;

import java.io.File;
import java.io.IOException;

/**
 * @author Mukul Puspam
 *
 * @param <U> Return type
 * 
 * @param <V> file path
 */

public interface VirusScanner<U, V> {

	/**
	 * Scan file.
	 *
	 * @param fileName the file name
	 * @return the u
	 */
	U scanFile(String fileName);

	U scanFile(V file);

	/**
	 * Scan folder.
	 *
	 * @param folderPath the folder path
	 * @return the u
	 */
	U scanFolder(String folderPath);

	/**
	 * Scan byte array.
	 *
	 * @param array array
	 * 
	 * @return the u
	 * 
	 * @throws IOException if exception occurs while failed or interrupted I/O
	 *                     operations
	 */
	U scanDocument(byte[] array) throws IOException;

	/**
	 * Scan File.
	 *
	 * @param doc object
	 * 
	 * @return the u
	 * 
	 * @throws IOException if exception occurs while failed or interrupted I/O
	 *                     operations
	 */
	U scanDocument(File doc) throws IOException;
}

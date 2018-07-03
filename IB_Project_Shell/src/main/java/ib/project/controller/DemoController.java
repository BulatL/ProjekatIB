package ib.project.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ResourceBundle;

import javax.servlet.ServletContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/demo", produces = MediaType.APPLICATION_JSON_VALUE)
public class DemoController {

	private static String DATA_DIR_PATH;

	@Autowired
	ServletContext context;

	static {
		ResourceBundle rb = ResourceBundle.getBundle("application");
		DATA_DIR_PATH = rb.getString("dataDir");
	}

	@RequestMapping(method = RequestMethod.POST)
	public ResponseEntity<String> createAFileInResources() throws IOException {

		byte[] content = "Content".getBytes();
		System.out.println("content: \n"+content);
		
		String directoryPath = getResourceFilePath(DATA_DIR_PATH).getAbsolutePath();
		System.out.println("directoryPath: \n"+directoryPath);
		Path path = Paths.get(directoryPath + File.separator + "demo.txt");
		System.out.println("path: \n"+path);
		Files.write(path, content);
		return new ResponseEntity<String>(path.toString(), HttpStatus.OK);
	}

	@RequestMapping(value = "/download", method = RequestMethod.GET)
	public ResponseEntity<byte[]> download() {

		ClassLoader classloader = Thread.currentThread().getContextClassLoader();

		URL urlPath = classloader.getResource(DATA_DIR_PATH + File.separator + "demo.txt");
		File file = null;
		try {
			file = new File(urlPath.getFile());
		}
		catch (Exception e) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		} 
		
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.add("filename", "demo.txt");

		byte[] bFile = readBytesFromFile(file.toString());

		return ResponseEntity.ok().headers(headers).body(bFile);
	}

	private static byte[] readBytesFromFile(String filePath) {

		FileInputStream fileInputStream = null;
		byte[] bytesArray = null;
		try {

			File file = new File(filePath);
			bytesArray = new byte[(int) file.length()];

			// read file into bytes[]
			fileInputStream = new FileInputStream(file);
			fileInputStream.read(bytesArray);

		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (fileInputStream != null) {
				try {
					fileInputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

		}

		return bytesArray;

	}

	public File getResourceFilePath(String path) {
		
		URL url = this.getClass().getClassLoader().getResource(path);
		File file = null;

		try {
			
			file = new File(url.toURI());
		} catch (Exception e) {
			file = new File(url.getPath());
		}

		return file;
	}
}

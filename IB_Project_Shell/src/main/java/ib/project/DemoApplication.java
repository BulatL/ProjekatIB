package ib.project;

import java.io.File;
import java.util.ResourceBundle;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import ib.project.controller.DemoController;

@SpringBootApplication
public class DemoApplication {

	private static String DATA_DIR_PATH;
	
	static {
		ResourceBundle rb = ResourceBundle.getBundle("application");
		DATA_DIR_PATH = rb.getString("dataDir");
	}
	
	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
		
		//create files folder in target/classes
		new File(DemoController.class.getProtectionDomain().getCodeSource().getLocation().getPath() + File.separator + DATA_DIR_PATH).mkdirs();
	}
}
 
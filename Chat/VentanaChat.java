import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class VentanaChat extends JFrame{
	
	private Container c;
	private JTextArea txtChat;
	private Button btnEnviar;
	private JTextField txtMensaje;
	private Cliente cliente;

	public VentanaChat(String nombre){
		super(nombre);
	    setSize(400,550);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
		c= getContentPane();
		c.setLayout(new FlowLayout());
		//Label l1 = new Label("Mensaje");
		txtChat= new JTextArea(30,30);
		txtMensaje= new JTextField(30);
		btnEnviar = new Button("Enviar");
		//c.add(l1);
		c.add(txtChat);
		//c.add(l1);
		c.add(txtMensaje);
		c.add(btnEnviar);
		btnEnviar.addActionListener(ListenerBoton);
		//pack();
		cliente =new Cliente();
		cliente.iniciarConeccion();
		this.setVisible(true);
	}

	ActionListener ListenerBoton =new ActionListener(){
		public void actionPerformed(ActionEvent e){
			cliente.enivarMensaje(txtMensaje.getText()+"\n");
			txtMensaje.setText("");
			System.out.println ("El mensaje fue enviado");
		}
	
	};



	public static void main(String args[]){
		new VentanaChat("Chat");
	}
}
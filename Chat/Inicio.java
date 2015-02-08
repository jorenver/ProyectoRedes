import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class Inicio extends JFrame{
	
	private Container c;
	private JTextField txtNombre;
	private Button btnConectar;

	public Inicio(){
		super("Iniciar Seccion");
	    setSize(300,300);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
		c= getContentPane();
		c.setLayout(new FlowLayout());
		Label l1 = new Label("Usuario");
		txtNombre= new JTextField(30);
		btnConectar = new Button("Conectar");
		btnConectar.addActionListener(ListenerBoton);
		c.add(l1);
		c.add(txtNombre);
		c.add(btnConectar);
		pack();
		setVisible(true);
	}

	ActionListener ListenerBoton =new ActionListener(){
		public void actionPerformed(ActionEvent e){
			new VentanaChat(txtNombre.getText());
			setVisible(false);
		}
	
	};

	public static void main(String args[]){
		new Inicio();
	}
}


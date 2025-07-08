// Ejercicio 1

import java.util.Stack;

public class Ejercicio1 {
    public static void main(String[] args) {
        Stack<Integer> pila = new Stack<>();

        pila.push(10);
        pila.push(20);
        pila.push(30);

        System.out.println("¿La pila está vacía? " + pila.isEmpty());

        System.out.println("Contenido de la pila: " + pila);
    }
}

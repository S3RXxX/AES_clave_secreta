class G_F:
    """
    Genera un cuerpo finito usando como polinomio irreducible el dado
    representado como un entero. Por defecto toma el polinomio del AES.
    Los elementos del cuerpo los representaremos por enteros 0<= n <= 255.
    """
    def __init__(self, Polinomio_Irreducible = 0x11B, verbose=False):
        '''
        Entrada: un entero que representa el polinomio para construir el cuerpo
        Tabla_EXP y Tabla_LOG dos tablas, la primera tal que en la posición
        i-ésima tenga valor a=g**i y la segunda tal que en la posición a-ésima
        tenga el valor i tal que a=g**i. (g generador del cuerpo finito
        representado por el menor entero entre 0 y 255.)
        '''
        self.verbose = verbose
        self.Polinomio_Irreducible = Polinomio_Irreducible
        self.Tabla_EXP, self.Tabla_LOG = self.__crear_Tablas(g=2)

    def __producto_lento(self, a, b):
        """Entrada:
        Salida"""
        res = 0
        for _ in range(8):
            if b & 1:
                res = res ^ a

            a = self.xTimes(a)

            b = b >> 1

        return res
    def __crear_Tablas(self, g):
        """Entrada:
        Salida:
        
        método auxiliar para crear las tablas"""
        t_exp = [1] + [0 for _ in range(255)]
        t_log = [0 for _ in range(256)]

        t_exp[1] = g
        t_log[g] = 1
        # calcular las tablas
        for i in range(2, 256):
            gi = self.__producto_lento(t_exp[i-1], g)
            t_exp[i] = gi
            if t_log[gi]:
                # comprovar que es un generador
                if self.verbose:
                    print(f"ciclo prematuro en {i} para el intento de generador g = {g} para el polinomio irreducible {self.Polinomio_Irreducible}")
                return self.__crear_Tablas(g=g+1)  # si g no es un generador, provar un valor mas grande
            
            t_log[gi] = i
        
        if self.verbose:
            print(f"GEnerador encontrado para el polinomio irreducible {self.Polinomio_Irreducible} es g={g}")
            print("t_exp", t_exp)
            print()
            print("t_log", t_log)
        
        return t_exp, t_log


    def xTimes(self, n):
        
        """Entrada: un elemento del cuerpo representado por un entero entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de 'n' y 0x02 (el polinomio X)."""
        aux = n << 1 # desplazar 1 bit
        if n >= 128:
            aux = aux ^ self.Polinomio_Irreducible
        return aux

    def producto(self, a, b):
        """Entrada: dos elementos del cuerpo representados por enteros entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de la entrada.
        Atención: Se valorará la eficiencia. No es lo mismo calcularlo
        usando la definición en términos de polinomios o calcular
        usando las tablas Tabla_EXP y Tabla_LOG."""
        if a == 0 or b == 0:
            return 0
        
        i = self.Tabla_LOG[a]
        j = self.Tabla_LOG[b]

        return self.Tabla_EXP[(i+j)%255]

    def inverso(self, n):
        """Entrada: un elementos del cuerpo representado por un entero entre 0 y 255
        Salida: 0 si la entrada es 0,
        el inverso multiplicativo de n representado por un entero entre
        1 y 255 si n <> 0.
        Atención: Se valorará la eficiencia."""
        if n==0:
            return 0

        i = self.Tabla_LOG[n]
        return self.Tabla_EXP[255-i]

# para comprovar: http://www.ee.unb.ca/cgi-bin/tervo/calc2.pl?num=1+0+7+6&den=1+6+3&f=m&p=2&d=1

if __name__ == "__main__":
    print("This file is designed to be imported in order to be used")

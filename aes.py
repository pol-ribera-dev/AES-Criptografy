import random

class G_F:
    """
    Genera un cuerpo finito usando como polinomio irreducible el dado
    representado como un entero. Por defecto toma el polinomio del AES.
    Los elementos del cuerpo los representaremos por enteros 0<= n <= 255.
    """
    def __init__(self, Polinomio_Irreducible = 0x11B):
        '''Entrada: un entero que representa el polinomio para construir el cuerpo
        Tabla_EXP y Tabla_LOG dos tablas, la primera tal que en la posici´on
        i-´esima tenga valor a=g**i y la segunda tal que en la posici´on a-´esima
        tenga el valor i tal que a=g**i. (g generador del cuerpo finito
        representado por el menor entero entre 0 y 255.)'''

        self.Polinomio_Irreducible = Polinomio_Irreducible
        self.Tabla_EXP = [0] * 256
        self.Tabla_LOG = [0] * 256
        g = 0x02
        while True:
            x = g
            found = True
            for i in range(1, 255):
                if x == 1:
                    found = False
                    break
                self.Tabla_EXP[i] = x
                self.Tabla_LOG[x] = i
                x = self.producto_lento(x, g)
            if x != 1 or found == False:
                g += 1
            else:
                self.Tabla_EXP[0] = 1
                self.Tabla_EXP[255] = 1
                self.Tabla_LOG[1] = 255
                break



    def producto_lento(self, a, b):
        """
        A partir de dos enteros calcula su producto lento, iteramos sobre los bits de un elemento, si es 1

        B1 * B2 = B1 * SUM(bi*x^i) = SUM(bi*x^i*B1)

        iteramos sobre los bits de b  #funció compartida amb el meu excompany ADRIA RUIZ
        """
        result = 0
        for bit in range(0, 8):
            if b % 2 != 0:
                mult = a
                for _ in range(bit):
                    mult = self.xTimes(mult)
                result ^= mult
            b >>= 1

        return result % self.Polinomio_Irreducible

    def xTimes(self, n): #n es la representació o un element del cos?
        '''Entrada: un elemento del cuerpo representado por un entero entre 0 y 255
            Salida: un elemento del cuerpo representado por un entero entre 0 y 255
            que es el producto en el cuerpo de ’n’ y 0x02 (el polinomio X).'''

        result = n << 1
        if result & 0x100:
            result ^= self.Polinomio_Irreducible
        return result & 0xFF


    def producto(self, a, b):

        '''Entrada: dos elementos del cuerpo representados por enteros entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de la entrada.
        Atenci´on: Se valorar´a la eficiencia. No es lo mismo calcularlo
        usando la definici´on en t´erminos de polinomios o calcular
        usando las tablas Tabla_EXP y Tabla_LOG.'''
        if a == 0 or b == 0:
            return 0

        log_a = self.Tabla_LOG[a]
        log_b = self.Tabla_LOG[b]

        result = (log_a + log_b) % 255

        return self.Tabla_EXP[result]

    def inverso(self, n):

        '''Entrada: un elementos del cuerpo representado por un entero entre 0 y 255
        Salida: 0 si la entrada es 0,
        el inverso multiplicativo de n representado por un entero entre
        1 y 255 si n <> 0.
        Atenci´on: Se valorar´a la eficiencia.'''
        if n == 0:
            return 0
        log_n = self.Tabla_LOG[n]
        inv_log_n = 255 - log_n
        return self.Tabla_EXP[inv_log_n]


class AES:
    '''
    Documento de referencia:
    Federal Information Processing Standards Publication (FIPS) 197: Advanced Encryption
    Standard (AES) https://doi.org/10.6028/NIST.FIPS.197-upd1
    El nombre de los m´etodos, tablas, etc son los mismos (salvo capitalizaci´on)
    que los empleados en el FIPS 197
    '''
    def __init__(self, key, Polinomio_Irreducible = 0x11B):
        '''
        Entrada:
        key: bytearray de 16 24 o 32 bytes
        Polinomio_Irreducible: Entero que representa el polinomio para construir
        el cuerpo
        SBox: equivalente a la tabla 4, p´ag. 14
        InvSBOX: equivalente a la tabla 6, p´ag. 23
        Rcon: equivalente a la tabla 5, p´ag. 17
        InvMixMatrix : equivalente a la matriz usada en 5.3.3, p´ag. 24
        '''
        self.Polinomio_Irreducible = Polinomio_Irreducible
        self.SBox = []
        self.my_GF = G_F(Polinomio_Irreducible)
        self.key = key
        for x in range(256):
            inv = self.my_GF.inverso(x)
            transformed_byte = 0x00
            for i in range (8):
                transformed_bit = (inv >> i) & 1
                for j in range(4,8):
                    mod = (i+j) % 8
                    transformed_bit ^= (inv >> mod) & 1
                transformed_byte |= transformed_bit * 2**i
            self.SBox.append(transformed_byte ^ 0x63)

        self.InvSBox = [0] * 256

        for i in range(256):
            self.InvSBox[self.SBox[i]] = i

        self.Rcon = [0] * 10
        valueRcon = [0x01, 0, 0, 0]
        for i in range(10):
            self.Rcon[i] = valueRcon
            valueRcon = [self.my_GF.xTimes(valueRcon[0]), 0, 0, 0]

        self.KEY_EXPANCION = self.KeyExpansion(self.key)
    def SubBytes(self, State):
        '''
        5.1.1 SUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            for j in range(4):
                State[i][j] = self.SBox[State[i][j]]
        return State
    def InvSubBytes(self, State):
        '''
        5.3.2 INVSUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            for j in range(4):
                State[i][j] = self.InvSBox[State[i][j]]
        return State
    def ShiftRows(self, State):
        '''
        5.1.2 SHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(1,4):
            for j in range(i):
                for k in range(3):
                    State[i][k], State[i][k+1] = State[i][k+1], State[i][k]
        return State
    def InvShiftRows(self, State):
        '''
        5.3.1 INVSHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        4
        '''
        for i in range(1, 4):
            for j in range(i):
                for k in range(3, 0, -1):
                    State[i][k], State[i][k - 1] = State[i][k - 1], State[i][k]
        return State
    def MixColumns(self, State):
        '''
        5.1.3 MIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        newState = [[0 for _ in range(4)] for _ in range(4)]

        for i in range(4):
                newState[0][i] = self.my_GF.producto(State[0][i],2) ^ self.my_GF.producto(State[1][i],3) ^ State[2][i] ^ State[3][i]
                newState[1][i] = self.my_GF.producto(State[1][i],2) ^ self.my_GF.producto(State[2][i],3) ^ State[0][i] ^ State[3][i]
                newState[2][i] = self.my_GF.producto(State[2][i],2) ^ self.my_GF.producto(State[3][i],3) ^ State[0][i] ^ State[1][i]
                newState[3][i] = self.my_GF.producto(State[3][i],2) ^ self.my_GF.producto(State[0][i],3) ^ State[2][i] ^ State[1][i]
        return newState

    def InvMixColumns(self, State):
        '''
        5.3.3 INVMIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        newState = [[0 for _ in range(4)] for _ in range(4)]

        for i in range(4):
            newState[0][i] = self.my_GF.producto(State[0][i], 0x0e) ^ self.my_GF.producto(State[1][i], 0x0b) ^ self.my_GF.producto(State[2][i], 0x0d) ^ self.my_GF.producto(State[3][i], 0x09)
            newState[1][i] = self.my_GF.producto(State[0][i], 0x09) ^ self.my_GF.producto(State[1][i], 0x0e) ^ self.my_GF.producto(State[2][i], 0x0b) ^ self.my_GF.producto(State[3][i], 0x0d)
            newState[2][i] = self.my_GF.producto(State[0][i], 0x0d) ^ self.my_GF.producto(State[1][i], 0x09) ^ self.my_GF.producto(State[2][i], 0x0e) ^ self.my_GF.producto(State[3][i], 0x0b)
            newState[3][i] = self.my_GF.producto(State[0][i], 0x0b) ^ self.my_GF.producto(State[1][i], 0x0d) ^ self.my_GF.producto(State[2][i], 0x09) ^ self.my_GF.producto(State[3][i], 0x0e)
        return newState

    def AddRoundKey(self, State, roundKey):
        '''
        5.1.4 ADDROUNDKEY()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            for j in range(4):
                State[j][i] ^= roundKey[i][j]
        return State

    def Rot_word(self, word):
        return word[1:] + word[:1]


    def Sub_word(self, word):
        return [self.SBox[byte] for byte in word]

    def KeyExpansion(self, key):
        '''
        5.2 KEYEXPANSION()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        Nk = int(len(key)/4)
        Nr = Nk + 6
        i = 0
        w = [0] * (4 * (Nr + 1))
        while i <= Nk - 1:
            w[i] = key[4 * i: 4 * i + 4]
            i += 1
        while i <= 4 * (Nr + 1) - 1:
            temp = [0,0,0,0]
            for j in range(4):
                temp[j] = w[i - 1][j]
            if i % Nk == 0:
                a = self.Sub_word(self.Rot_word(temp))
                b = self.Rcon[int(i / Nk) - 1]
                for j in range(4):
                    temp[j] = a[j] ^ b[j]
            elif Nk > 6 and i % Nk == 4:
                temp = self.Sub_word(temp)
            c = w[i - Nk]
            d = temp
            g = [0,0,0,0]
            for j in range(4):
                g[j] = c[j] ^ d[j]
            w[i] = g
            i += 1

        return w


    def Cipher(self, State, Nr, Expanded_KEY):
        '''
        5.1 Cipher(), Algorithm 1 p´ag. 12
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        State = self.AddRoundKey(State, Expanded_KEY[0:4])

        for round in range(1, Nr):
            State = self.SubBytes(State)
            State = self.ShiftRows(State)
            State = self.MixColumns(State)
            State = self.AddRoundKey(State, Expanded_KEY[4 * round: 4 * (round + 3)])
        State = self.SubBytes(State)
        State = self.ShiftRows(State)
        State = self.AddRoundKey(State, Expanded_KEY[4 * Nr: 4 * (Nr + 3)])

        return State

    def InvCipher(self, State, Nr, Expanded_KEY):
        '''
        5. InvCipher()
        Algorithm 3 p´ag. 20 o Algorithm 4 p´ag. 25. Son equivalentes
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        State = self.AddRoundKey(State, Expanded_KEY[4 * Nr: 4 * (Nr + 3)])

        for round in range(Nr-1, 0, -1):
            State = self.InvShiftRows(State)
            State = self.InvSubBytes(State)
            State = self.AddRoundKey(State, Expanded_KEY[4 * round: 4 * (round + 3)])
            State = self.InvMixColumns(State)
        State = self.InvShiftRows(State)
        State = self.InvSubBytes(State)
        State = self.AddRoundKey(State, Expanded_KEY[0:4])

        return State

    def encrypt_file(self, fichero):
        '''
        Entrada: Nombre del fichero a cifrar
        Salida: Fichero cifrado usando la clave utilizada en el constructor
        de la clase.
        Para cifrar se usara el modo CBC, con IV generado aleatoriamente
        y guardado en los 16 primeros bytes del fichero cifrado.
        El padding usado sera PKCS7.
        El nombre de fichero cifrado sera el obtenido al anadir el sufijo .enc
        al nombre del fichero a cifrar: NombreFichero --> NombreFichero.enc
        '''
        Nk = len(self.key)
        Nr = int(Nk / 4) + 6
        iv = [[random.randint(0, 255) for _ in range(4)] for _ in range(4)]
        with open(fichero, 'rb') as f:
            file_data = f.read()
        padding_length = 16 - len(file_data) % 16
        file_data += bytes([padding_length] * padding_length)
        lista_bytes = list(bytearray(file_data))
        encrypted_file = fichero + '.enc'
        result = []
        for i in range(4):
            for j in range(4):
                result.append(iv[j][i])
        for n in range(int(len(lista_bytes)/16)):
            State = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
            for i in range(4):
                for j in range(4):
                    State[j][i] = lista_bytes[n * 16 + i * 4 + j] ^ iv[j][i]
            iv = self.Cipher(State, Nr, self.KEY_EXPANCION)
            for i in range(4):
                for j in range(4):
                    result.append(iv[j][i])
        with open(encrypted_file, 'wb') as f_enc:
            f_enc.write(bytes(result))
        print(f"El archivo {fichero} ha sido cifrado y guardado como {encrypted_file}.")

    def decrypt_file(self, fichero):
        '''
        Entrada: Nombre del fichero a descifrar
        Salida: Fichero descifrado usando la clave utilizada en el constructor
        de la clase.
        Para descifrar se usar´a el modo CBC, con el IV guardado en los 16
        primeros bytes del fichero cifrado, y se eliminar´a el padding
        PKCS7 a~nadido al cifrar el fichero.
        El nombre de fichero descifrado ser´a el obtenido al a~nadir el sufijo .dec
        al nombre del fichero a descifrar: NombreFichero --> NombreFichero.dec
        '''

        with open(fichero, 'rb') as f_enc:
            file_data = f_enc.read()
        Nk = len(self.key)
        Nr = int(Nk/4) + 6
        decrypted_file = fichero + '.dec'
        """
        Per alguna rao l'exemple que ens poseu només funciona si llegeixes les dades així
        data_str = file_data.decode('utf-8').replace('\n', '').replace(' ', '')
        hex_pairs = [data_str[i:i + 2] for i in range(0, len(data_str), 2)]
        datos = [int(byte, 16) for byte in hex_pairs]
        """
        datos = list(file_data)
        first = True
        result = [0] * (len(datos)-16)
        State = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
        for n in range(int(len(datos)/16)-1, 0, -1):
            Anterior = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
            for i in range(4):
                for j in range(4):
                    Anterior[j][i] = datos[(n-1) * 16 + i * 4 + j]
                    if first:
                        State[j][i] = datos[n * 16 + i * 4 + j]
            State = self.InvCipher(State, Nr, self.KEY_EXPANCION)
            if first:
                first = False
            for i in range(4):
                for j in range(4):
                    State[i][j] = State[i][j] ^ Anterior[i][j]
            for i in range(4):
                for j in range(4):
                    result[(n-1) * 16 + i * 4 + j] = State[j][i]
            State = Anterior

        a = result[-1]
        for i in range(a):
            result = result[:-1]

        with open(decrypted_file, 'wb') as f_dec:
                f_dec.write(bytes(result))

        print(f"El archivo {fichero} ha sido descifrado y guardado como {decrypted_file}.")
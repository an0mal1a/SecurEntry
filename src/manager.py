import os
import secrets
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import pathlib
import shutil
import sys
import requests
import json
import tempfile
from pathlib import Path
import PySimpleGUI as Sg
import sqlite3
import string
import random
import threading

# Testear acceso a memoria

file = ""
options = ['unused', ['Open Generator', '---', 'Robust', 'Medium', 'Low']]
right_option_click = ['unused', ['Add Entry', '---', 'Edit Entry', 'Copy Username', 'Copy Password']]
database_info = []
temp = tempfile.NamedTemporaryFile(delete=False)
temp.close()
fileDatabaseExample = Path.home()
action = False

# Config Files
path = str(pathlib.Path.home()) + "\\SecurEntry"
imgPath = path + "\\images"
configPath = path + "\\data"


class passwordstrength:
    def __init__(self, password, verbose=False):
        #self.words = words  # why?

        self.password = password
        self.password_length = len(password)

        self.verbose = verbose
        if verbose:
            print("{:>45s}{:>13s}".format("Count", "Value"))
            print('=' * 80)

        # Calculating the score
        self.score = sum((
            self.__length_score(),
            self.__lower_upper_case_score(),
            self.__digits_score(),
            self.__special_score(),
            self.__middle_score(),
            self.__letters_only_score(),
            self.__numbers_only_score(),
            self.__repeating_chars_score(),
            self.__consecutive_case_score(),
            self.__sequential_letters_score(),
            self.__sequential_numbers_score(),
            #self.__dictionary_words_score(),
            self.__extra_score()
        ))

        if verbose:
            print('-' * 80)
            print("{:>45s}{}{:=+4d}".format("Total", ' ' * 8, self.score))

    def __table_print(self, title, count, value):
        if self.verbose:
            title = title.capitalize()
            count = str(count)

            print("{title:40s}{count:13s}{value:=+4d}".format(**locals()))

    def __chars_of_type(self, chartype):
        chartype_count = 0
        for char in self.password:
            if char in chartype:
                chartype_count += 1

        return chartype_count

    def __length_score(self):
        self.__table_print('length', self.password_length, self.password_length * 4)

        return self.password_length * 4  # The way WA works.

    def __lower_upper_case_score(self):
        # This will return the number of upper and lower case characters,
        # if at least one of each is available.
        n_upper = self.__chars_of_type(string.ascii_uppercase)
        n_lower = self.__chars_of_type(string.ascii_lowercase)

        upper_score = 0 if not n_upper else (self.password_length - n_upper) * 2
        lower_score = 0 if not n_lower else (self.password_length - n_lower) * 2

        self.__table_print('upper case letters', n_upper, upper_score)
        self.__table_print('lower case letters', n_lower, lower_score)

        if lower_score and upper_score:
            return lower_score + upper_score

        return 0

    def __digits_score(self):
        digit_count = self.__chars_of_type(string.digits)

        self.__table_print('numbers', digit_count, digit_count * 4)

        return digit_count * 4  # The way WA works.

    def __special_score(self):
        special_char_count = self.__chars_of_type(string.punctuation)

        self.__table_print('special characters', special_char_count,
                           special_char_count * 6)

        return special_char_count * 6  # The way WA works.

    def __middle_score(self):
        # WA doesn't count special characters in this score (which probably
        # is a mistake), but we will.
        middle_chars_count = 0

        middle_chars = set(string.punctuation + string.digits)

        for char in self.password[1:-1]:
            if char in middle_chars:
                middle_chars_count += 1

        self.__table_print('middle numbers or special characters',
                           middle_chars_count, middle_chars_count * 2)

        return middle_chars_count * 2  # The way WA works

    def __letters_only_score(self):
        letter_count = self.__chars_of_type(string.ascii_lowercase + string.ascii_uppercase)

        if self.password_length == letter_count:
            self.__table_print('letters only', 'yes', -self.password_length)

            # If the password is all letters, return the negative
            # of the password length. The way WA works.
            return -self.password_length

        self.__table_print('letters only', 'no', 0)

        # If the password contains something else than letters,
        # don't affect the score.
        return 0

    def __numbers_only_score(self):
        digit_count = self.__chars_of_type(string.digits)

        if self.password_length == digit_count:
            self.__table_print('numbers only', 'yes', -self.password_length)

            # If the password is all numbers, return the negative
            # form of the password length. The way WA works.
            return -self.password_length

        self.__table_print('numbers only', 'no', 0)

        # If the password contains something else than numbers,
        # don't affect the score.
        return 0

    def __repeating_chars_score(self):
        repeating_char_count = self.password_length - len(set(self.password))

        self.__table_print('repeating characters', repeating_char_count,
                           -repeating_char_count)

        return -repeating_char_count  # The way WA works

    def __consecutive_case_score(self):
        char_types = {
            string.ascii_lowercase: 0,
            string.ascii_uppercase: 0,
            string.digits: 0,
        }

        for c1, c2 in zip(self.password, self.password[1:]):
            # zips match the length of the shorter by default

            for char_type in char_types:
                if c1 in char_type and c2 in char_type:
                    char_types[char_type] += 1

        self.__table_print('consecutive upper-case letters',
                           char_types[string.ascii_uppercase],
                           -2 * char_types[string.ascii_uppercase])

        self.__table_print('consecutive lower-case letters',
                           char_types[string.ascii_lowercase],
                           -2 * char_types[string.ascii_lowercase])

        self.__table_print('consecutive numbers',
                           char_types[string.digits],
                           -2 * char_types[string.digits])

        return -2 * sum(char_types.values())  # The way WA works

    def __sequential_numbers_score(self):
        sequential_number_count = 0

        for i in range(1000):
            if str(i) + str(i + 1) in self.password:
                sequential_number_count += 2

        self.__table_print('sequential numbers', sequential_number_count,
                           -sequential_number_count * 2)

        return -sequential_number_count * 2

    def __sequential_letters_score(self):
        password = self.password.lower()

        sequential_letter_count = 0

        seeing = False
        for c1, c2 in zip(password, password[1:]):
            # zips match the length of the shorter by default
            if ord(c1) + 1 == ord(c2) and c1 in string.ascii_lowercase[:-1]:
                sequential_letter_count += 1

                if not seeing:
                    # until now, we weren't in a pocket of sequential letters
                    sequential_letter_count += 1
                    seeing = True
            else:
                # we've seen a whole pocket, and counted everything
                seeing = False

        sequential_letter_count -= 2  # The way WA works

        if sequential_letter_count > 0:
            self.__table_print('sequential letters',
                               sequential_letter_count,
                               sequential_letter_count * -2)

            return sequential_letter_count * -2  # The way WA works

        self.__table_print('sequential letters', 0, 0)

        return 0

    def __substrings(self, word):
        # generate all substrings of length at least 3
        for i in range(len(word)):
            for j in range(i + 3, len(word) + 1):
                yield word[i:j]

    def __extra_score(self):
        if self.password_length < 8:
            self.__table_print('extra criteria', 'no', 0)
            return 0

        upper = False
        lower = False
        special = False
        number = False

        for char in self.password:
            if char in string.ascii_uppercase:
                upper = True
            elif char in string.ascii_lowercase:
                lower = True
            elif char in string.punctuation:
                special = True
            elif char in string.digits:
                number = True

        if upper and lower and (special or number):
            self.__table_print('extra criteria', 'yes', 8)

            return 8

        return 0

    def get_score(self):
        return self.score


def getNames():
    url = "https://github.com/an0mal1a/SecurEntry/tree/main/src/images"
    req = requests.get(url)
    data = req.content

    jsonData = json.loads(data.decode())
    names = []
    for img in jsonData['payload']['tree']['items']:
        names.append(img['name'])
    return names


def dloadImg(names):
    color_gris_claro = '#cdcdcd'
    color_gris_fondo_claro = "#f0f0f0"
    Sg.theme_add_new('chill', {'BACKGROUND': color_gris_fondo_claro,
                               'TEXT': 'black',
                               'INPUT': 'white',
                               'TEXT_INPUT': 'black',
                               'SCROLL': color_gris_claro,  # Color de la barra de movimiento del Multiline
                               'BUTTON': ('black', color_gris_claro),
                               'PROGRESS': ('white', color_gris_claro),
                               'BORDER': 1,
                               'SLIDER_DEPTH': 0,
                               'PROGRESS_DEPTH': 0})
    Sg.theme('chill')
    url = "https://raw.githubusercontent.com/an0mal1a/SecurEntry/main/src/images/"

    # Crear una ventana con una barra de progreso
    layout = [[Sg.Text('Descargando imágen', key="txt")],
              [Sg.ProgressBar(len(names), orientation='h', size=(20, 20), key='progressbar', bar_color=("green", "white"))],
              ]
    window = Sg.Window('Descargando resources', layout, size=(400,100))

    progress_bar = window['progressbar']

    for i, name in enumerate(names):
        if name not in os.listdir(imgPath):
            print("Descargando ---- {}".format(name))
            with open(f"{imgPath}/{name}", "wb") as f:
                time.sleep(0.3)
                req = requests.get(url + name)
                f.write(req.content)
            f.close()

            # Actualizar la barra de progreso
            event, values = window.read(timeout=0)
            if event == 'Cancel' or event == Sg.WIN_CLOSED:
                break

            window['txt'].update("Descargando imágen -- {}".format(name))
            progress_bar.UpdateBar(i + 1)

        else:
            pass

    window.close()
    print("Fin")


def startDload():
    names = getNames()

    dloadImg(names)


def init_decrypt_file(file, key):
    try:
        with open(file, "rb") as f:
            content = f.read()
        key = key.encode()
        key = generate_key_from_password_256(key)

        decrypted_file_data = decrypt(content, key)

        with open(file, "wb") as f:
            f.write(decrypted_file_data)

    except ValueError:
        return 1


def init_crypt_file(file, key):
    with open(file, "rb") as f:
        content = f.read()

    if not key:
        key = secrets.token_bytes(32)

    else:
        # Generamos clave y la encriptamos
        key = key.encode()
        key = generate_key_from_password_256(key)

    encrypted_file_data = encrypt(content, key)
    #print(encrypted_file_data, " | " ,key,"\n")

    with open(file, "wb") as f:
        f.write(encrypted_file_data)



def generate_key_from_password_256(password):
    salt = base64.b64decode(b'azR5cDcwLlM0bHRJbmQ0dA==')
    #salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key


def generate_key_from_password_512(password):
    salt = base64.b64decode(b'azR5cDcwLlM0bHRJbmQ0dA==')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key


def decrypt(encrypted_data, key):
    init_vector = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector), backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(message)


def encrypt(content, key):
    message = pad(content)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext


def pad(message):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message)
    padded_message += padder.finalize()
    return padded_message


def unpad(message):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(message)
    unpadded_message += unpadder.finalize()
    return unpadded_message


def checkStart():
    global fileDatabaseExample
    if not os.path.exists(path):
        os.makedirs(path)
    if not os.path.exists(configPath):
        os.makedirs(configPath)
    if not os.path.exists(imgPath):
        os.makedirs(imgPath)
    startDload()
    if os.path.exists(configPath + "\\dbName"):
        with open(configPath + "\\dbName") as f:
            fileDatabaseExample = f.read()
        f.close()
    if not fileDatabaseExample:
        fileDatabaseExample = Path.home()



def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return str(os.path.join(base_path, relative_path))


def get_pass(lenght, window1, master=False, values="all"):
    passwrd = rndom_passwrd(int(lenght), values)
    if master:
        window1['-master-password-'].update(passwrd)
        window1['-masterpassword-'].update(passwrd)
    else:
        window1['password'].update(passwrd)
        window1['-password-'].update(passwrd)
    return passwrd


def rndom_passwrd(lenght, values="all"):
    all_chars = []
    upper = list(string.ascii_lowercase)
    lower = list(string.ascii_uppercase)
    digits = list(string.digits)
    minus = ["-"]
    underline = ["_"]
    special = ["!", '"', "%", "$", "&", "'", "*", "+", ",", ".", ":", ";", "=", "?", "¿", "¡", "\\", "|", "`", "~", "#"]
    brakets = ["[", "]", "{", "}", "<", ">", "(", ")"]
    space = [" "]

    if values == "all":
        all_chars = upper + lower + digits + minus + underline + special + brakets + space
    else:
        for value in values:
            if value == 'upper':
                all_chars.extend(upper)
            elif value == 'lower':
                all_chars.extend(lower)
            elif value == 'digits':
                all_chars.extend(digits)
            elif value == 'minus':
                all_chars.extend(minus)
            elif value == 'underline':
                all_chars.extend(underline)
            elif value == 'special':
                all_chars.extend(special)
            elif value == 'brakets':
                all_chars.extend(brakets)
            elif value == 'space':
                all_chars.extend(space)

    passwrd = "".join(random.choice(all_chars) for _ in range(lenght))
    return passwrd


def write_password(password, user, title, url, used, notes, quality, tables_info):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    id_t = len(tables_info)

    query = "INSERT INTO {} (id, title, username, password, url, notes, quality) VALUES (?, ?, ?, ?, ?, ?, ?)".format(used)
    values = (id_t, title, user, password, url, notes, quality)
    c.execute(query, values)

    conn.commit()
    conn.close()


def update_password(password, user, title, url, used, notes, quality, id_t):
    try:

        conn = sqlite3.connect(db_file)
        c = conn.cursor()

        # Buscar la entrada existente en la tabla y actualizarla
        query = f"UPDATE {used} SET password=?, username=?, title=?, url=?, notes=? quality=? WHERE id=?"
        values = (password, user, title, url, notes, quality, id_t)

        c.execute(query, values)

        conn.commit()
        conn.close()

        return True

    except Exception:
        return False


def generate_random_password(lenght, window1, values="all"):
    passwd = get_pass(lenght, window1, values=values)
    return passwd
    #window.finalize()


def delete_sql_entry(title, id_column, used):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    if used != "Papelera":
        # Mover a la papelera
        query_move = f"INSERT INTO Papelera SELECT * FROM {used} WHERE id = ?"
        values_move = (id_column, )
        c.execute(query_move, values_move)

        # Eliminar de la tabla original (usar un marcador de posición para el nombre de la tabla)
        query_del = "DELETE FROM {table} WHERE id = :id".format(table=used)
        values_del = {"id": id_column}
        c.execute(query_del, values_del)

    else:
        confirm = delete_popup(title, id_column, used)
        if confirm == 0:
            # Eliminar de la papelera
            query_delete = f"DELETE FROM 'Papelera' WHERE id = ?"
            values_delete = (id_column, )
            c.execute(query_delete, values_delete)

    conn.commit()
    c.close()


def delete_popup(title, id_column, used):
    delete_layout = [
        [Sg.Text("\n¡Vas a eliminar una contraseña!", text_color="red", justification="center", pad=((2, 2), (4, 4)),
                 font=("Arial", 12))],

        [Sg.Text(f"\tPor seguridad, introduce el título de la entrada",)],
        [Sg.Text(f"\t\t{title}", font=("Poppins", 14))],

        # Confirmar entrada
        [Sg.Text("Enter Title: "), Sg.Input("", key="confirm_delete")],

        # Boton confirmar
        [Sg.Button("Confirmar", key="action", pad=(2, 1), button_color=color_gris_claro, mouseover_colors="#C2FFFE",
                   border_width=1, font=button_font, size=button_size)]

    ]

    delete_window = Sg.Window("CONFIRM DELETE", layout=delete_layout)

    while True:
        delete_events, delete_values = delete_window.read()
        print(delete_events, delete_values)

        if delete_events == Sg.WIN_CLOSED:
            delete_window.close()
            break

        # Crear logica de los botones!*
        elif delete_events == "action" and delete_values['confirm_delete']:
            compare_title = delete_values['confirm_delete']
            if title == compare_title:
                delete_window.close()
                return 0
            else:
                delete_window.close()
                return 1


def generatorPassword(values, lenght):
    newValues = []
    opts = ["upper", "lower", "digits", "special", "space", "brakets", "minus", "underline"]

    for v in values:
        if v in opts:
            if values[v]:
                newValues.append([v][0])
    return rndom_passwrd(lenght, values=newValues)


def disable_derive_elements(window, disabled, id):
    if id == 1:
        keys = ["upper", "lower", "digits", "special", "space", "brakets", "minus", "underline"]
    else:
        keys = ["derive", "random"]

    for key in keys:
        window[key].update(disabled=disabled)


def changeLength(values1, window1):
    if values1['option'] == "Robust":
        window1['-length-'].update(24)
        window1['brakets'].update(True)
        window1['space'].update(True)
        window1['upper'].update(True)
        window1['lower'].update(True)
        window1['digits'].update(True)
        window1['special'].update(True)
        window1['minus'].update(True)
        window1['underline'].update(True)

    elif values1['option'] == "Medium":
        window1['-length-'].update(18)
        window1['brakets'].update(False)
        window1['space'].update(False)
        window1['upper'].update(True)
        window1['lower'].update(True)
        window1['digits'].update(True)
        window1['special'].update(True)
        window1['minus'].update(True)
        window1['underline'].update(True)


    elif values1['option'] == "Low":
        window1['-length-'].update(12)
        window1['brakets'].update(False)
        window1['space'].update(False)
        window1['special'].update(False)
        window1['minus'].update(False)
        window1['underline'].update(False)
        window1['upper'].update(True)
        window1['lower'].update(True)
        window1['digits'].update(True)


def derivePasswd(original_password, rand=False):
    all_chars = list(string.ascii_lowercase) + list(string.ascii_uppercase) + list(string.digits) + ["-"] + ["_"] + ["!", '"', "%", "$", "&", "'", "*", "+", ",", ".", ":", ";", "=", "?", "¿", "¡", "\\", "|", "`", "~", "#"] + ["[", "]", "{", "}", "<", ">", "(", ")"] + [" "]
    derived_password = ""
    hops = random.randint(3, 10)

    for i, char in enumerate(original_password):
        hop = random.randint(3, 10) if rand else hops  # Saltos aleatorios si rand=True, 1 salto si rand=False
        char_index = all_chars.index(char)
        new_char_index = (char_index + hop) % len(all_chars)
        derived_password += all_chars[new_char_index]

    return derived_password


def makeChanges(values1, window1):
    if values1['mod'] is True:
        p = generatorPassword(values1, values1["-length-"])
        window1.close()
        return p

    elif values1['der'] is True:
        derive = values1['derive']
        if values1['random'] is True: window1.close(); return derivePasswd(derive, rand=True)
        else: window1.close(); return derivePasswd(derive)


def GeneratorPopup():
    Sg.theme_add_new('chill', {'BACKGROUND': color_gris_fondo_claro,
                               'TEXT': 'black',
                               'INPUT': 'white',
                               'TEXT_INPUT': 'black',
                               'SCROLL': color_gris_claro,  # Color de la barra de movimiento del Multiline
                               'BUTTON': ('black', color_gris_claro),
                               'PROGRESS': ('white', color_gris_claro),
                               'BORDER': 1,
                               'SLIDER_DEPTH': 0,
                               'PROGRESS_DEPTH': 0})



    # Variables para layout
    txtFnt = ("Poppins", 9, "bold")
    Sg.set_options(font=("Poppins", 9))
    Sg.theme('chill')

    default_title = "Password Generator"


    optionsLayout = [[Sg.Checkbox("UpperCase (A, B, ...)", key="upper", checkbox_color="white", enable_events=True, default=True),
                        Sg.Checkbox("LowerCase (a, b, c, ...)", key="lower", checkbox_color="white", enable_events=True, default=True),
                        Sg.Checkbox("Digits (0, 1, 2, ...)", key="digits",  checkbox_color="white", enable_events=True, default=True),
                      ],


                    [Sg.Checkbox("Special (!, \, |, %, ...)", key="special", checkbox_color="white", enable_events=True, default=True, tooltip="! \" % $ & ' * + , . : ; = ? ¿ ¡ \ | ` ~ #"),
                        Sg.Checkbox("Space ( )", key="space", checkbox_color="white", enable_events=True, default=True),
                        Sg.Checkbox("Brakets ([, ], {, })", key="brakets", checkbox_color="white", enable_events=True, default=True, tooltip="[ ] { } < > ( )"),],

                    [Sg.Checkbox("Minus (-)", key="minus", checkbox_color="white", enable_events=True, default=True),
                        Sg.Checkbox("Underline (_)", key="underline", checkbox_color="white", enable_events=True, default=True)]
                     ]

    deriveLayout = [
        [Sg.Input("", key='derive', size=(45, 1), disabled=True)],
        [Sg.Checkbox("Permute Randomly Charset of Password", key="random", enable_events=True, disabled=True)]
    ]

    allLayout = [

        # Modificator
        [Sg.Radio("Generate Using Modificator", default=True, group_id="opt", key="mod", enable_events=True, font=txtFnt)],
        [Sg.Text(" " * 5), Sg.Frame("SecureGenerator", optionsLayout, expand_x=True, expand_y=True,
                                    title_location=(Sg.TITLE_LOCATION_TOP_RIGHT))],

        # Derive
        [Sg.Radio("Derive From Password", default=False, group_id="opt", key="der", enable_events=True, font=txtFnt)],
        [Sg.Text(" " * 5), Sg.Frame("SecureDerive", deriveLayout, expand_x=True, expand_y=True, title_location=(Sg.TITLE_LOCATION_TOP_RIGHT))],

       ]


    # lo que se muestra:
    layout = [[
        Sg.Image(resource_path(f'{imgPath}/passgen.png'), key="image", size=(68, 68)),
        Sg.T('     GENERATE PASSWORD ', text_color='red', justification="center", pad=((2, 2), (4, 4)), font=("Arial", 12, "bold"))],
        # Titulo de la contraseña
        [Sg.Text("Profile:           ", font=txtFnt), Sg.Combo(["Robust", "Medium", "Low"], key="option", size=(43, 1), default_value="Robust",
                                                  readonly=True, button_background_color="#94b8b8", background_color="#DCDCDC", enable_events=True)],
        [Sg.Text("Password Length:    ", font=txtFnt),
         Sg.Spin(list(range(4, 128)), initial_value=24, enable_events=True, key="-length-")],
        [Sg.HSeparator()],

        # Main frame
        [Sg.Frame("Password Generator", allLayout, expand_x=True, expand_y=True, title_color='red')],

        # Boton de cancelar
        [Sg.Button("Cancelar", key='cancel', pad=(2, 1), button_color=color_gris_claro, mouseover_colors="#C2FFFE",
                   border_width=1, font=button_font, size=button_size),
         # Boton de aceptar
         Sg.Button("OK", key='accept', pad=(2, 1), button_color=color_gris_claro, mouseover_colors="#C2FFFE",
                   border_width=1, font=button_font, size=button_size, ),
         ]

    ]

    window1 = Sg.Window(default_title, layout, border_depth=2, icon=resource_path(f"{imgPath}/security.ico"))

    while True:
        event1, values1 = window1.read()
        print(event1, values1)

        # Cerrar con la X
        if event1 == Sg.WIN_CLOSED:
            break

        if event1 == "accept":
            p = makeChanges(values1, window1)
            break

        elif event1 == "cancel":
            window1.close()
            break

        elif event1 == "mod":
            disable_derive_elements(window1, True, 2)
            disable_derive_elements(window1, False, 1)

        elif event1 == "der":
            disable_derive_elements(window1, True, 1)
            disable_derive_elements(window1, False, 2)

        elif event1 == "option":
            changeLength(values1, window1)

    try:
        return p
    except UnboundLocalError:
        window1.close()
        return None


def setQuality(passw, window1):
    strength = passwordstrength(passw)
    punct = strength.get_score()
    window1['-PROGRESS-'].update(punct)
    window1['-quality-'].update(punct)
    return strength


def main_entry(used, entry_data, db_file, tables_info):
    do = None
    if entry_data:
        id_column = entry_data[0]
    else:
        id_column = ""

    try:
        title = entry_data[1]
    except IndexError:
        title = ""
    try:
        user = entry_data[2]
    except IndexError:
        user = ""
    try:
        password = entry_data[3]
    except IndexError:
        password = ""
    try:
        url = entry_data[4]
    except IndexError:
        url = ""
    try:
        notes = entry_data[5]
    except IndexError:
        notes = ""
    try:
        quality = entry_data[6]
    except:
        quality = ""

    global window
    check_database(db_file)

    Sg.theme_add_new('chill', {'BACKGROUND': color_gris_fondo_claro,
                               'TEXT': 'black',
                               'INPUT': 'white',
                               'TEXT_INPUT': 'black',
                               'SCROLL': color_gris_claro,  # Color de la barra de movimiento del Multiline
                               'BUTTON': ('black', color_gris_claro),
                               'PROGRESS': ('white', color_gris_claro),
                               'BORDER': 1,
                               'SLIDER_DEPTH': 0,
                               'PROGRESS_DEPTH': 0})

    # Variables para layout
    Sg.set_options(font=("Poppins", 9))
    txtFnt = ("Poppins", 9, "bold")
    Sg.theme('chill')
    options = ['unused', ['Open Generator', '---', 'Robust', 'Medium', 'Low']]


    default_title = "Add Entry"

    inputsLayout = [
        # Titulo de la contraseña
        [Sg.Text("Title:                ", font=txtFnt), Sg.Input(title, key="title", size=(45, 1))],
        # Usuario
        [Sg.Text("User name:   ", font=txtFnt), Sg.Input(user, key='user', size=(45, 1))],

        # Contraseña
        [Sg.Text("Password:    ", font=txtFnt),
         Sg.Input(password, key='password', password_char='•', size=(40, 1), enable_events=True),
         # Mostramos o ocultamos la contrasela
         Sg.Button("", key="show_password", image_filename=resource_path(f'{imgPath}/eye_icon1.png'),
                   mouseover_colors="#CCE8FF", button_color=color_gris_claro, tooltip="Show / Hide", size=button_size,
                   font=button_font), ],

        # Confirmacion de contraseña
        [Sg.Text("Repeat:          ", font=txtFnt),
         Sg.Input(password, key='-password-', password_char='•', size=(40, 1)),
         # Generador de contraselas
         Sg.ButtonMenu('', options, key='submenu', button_color=color_gris_claro,
                       image_filename=resource_path(f"{imgPath}/generate.png"), tooltip="Generator")],
        # Calidad de contraseña
        [Sg.Text("Quality:          ", font=txtFnt),
         Sg.ProgressBar(256, orientation='h', size=(26, 20), key='-PROGRESS-', bar_color=("green", "white"),
                        border_width=1, expand_x=True, expand_y=True),
         Sg.Text("", key="-quality-", font=button_font)],

        # URL
        [Sg.Text("URL:               ", font=txtFnt), Sg.Input(url, key='url', size=(45, 1))],

        # Comentarios o notas
        [Sg.Text("Notes:           ", font=txtFnt),
         Sg.Multiline(notes, size=(45, 10), key='notes', border_width=2), ],
    ]

    # lo que se muestra:
    layout = [[
        Sg.Image(resource_path(f'{imgPath}/1.png'), key="image1"),
        Sg.T('SAVE PASSWORD ', text_color='red', justification="center", pad=((2, 2), (4, 4)), font=("Arial", 14, "bold"))],

        [Sg.Frame("Saving Password", inputsLayout)],

        # Boton de cancelar
        [Sg.Button("Cancelar", key='cancel', pad=(2, 1), button_color=color_gris_claro, mouseover_colors="#C2FFFE",
                   border_width=1, font=button_font, size=button_size),
         #Boton de aceptar
         Sg.Button("Aceptar", key='accept', pad=(2, 1), button_color=color_gris_claro, mouseover_colors="#C2FFFE",
                   border_width=1, font=button_font, size=button_size, ),


         # Separador del boton delete
         Sg.Text(" " * 82,),

         # Boton delete
         Sg.Button("Delete", key="delete", pad=(2, 1), button_color="red", mouseover_colors="#C2FFFE",
                   border_width=1, font=button_font, size=button_size)
         ],
    ]

    if entry_data:
        default_title = "Edit Entry"

    else:
        buttons = layout[-1]
        buttons.remove(buttons[3])

    show_password  = False  # Variable para almacenar la ventana emergente de submenú
    window1 = Sg.Window(default_title, layout, border_depth=2, icon=resource_path(f"{imgPath}/security.ico"), resizable=False)

    while True:
        event1, values1 = window1.read(timeout=1000)
        print(event1, values1)
        # Cerrar con la X
        if event1 == "__TIMEOUT__" and do is None:
            window1['-PROGRESS-'].update(quality)
            strength = setQuality(values1['password'], window1)
            do = True

        elif event1 == Sg.WIN_CLOSED:
            break

        # Generar contraseña random
        elif event1 == 'cancel':
            break

        elif event1 == "password":
            strength = setQuality(values1['password'], window1)

        # Guardar y continuar
        elif event1 == "accept":
            # No coinciden...
            if values1['password'] != values1['-password-']:
                Sg.popup("Contraseñas NO coninciden...",
                         title="Passwords doesn't match", icon=resource_path(f"{imgPath}/security.ico"))

            # Contraseña VACIA
            elif values1['password'] == "":
                Sg.popup("No has introducido una contraseña. \n\nRecuerda que puedes generar una cuando lo necesites",
                         title='Empty Password', icon=resource_path(f"{imgPath}/security.ico"))

            # Guardamos y cerramos...
            else:
                # valores para la contraseña
                title_l = values1['title']
                password_l = values1['password']
                user_l = values1['user']
                url_l = values1['url']
                notes_l = values1['notes']
                quality = strength.get_score()

                if entry_data:
                    update_password(password_l, user_l, title_l, url_l, used, notes_l, quality, id_column)
                    window1.close()

                else:
                    write_password(password_l, user_l, title_l, url_l, used, notes_l, quality, tables_info)
                    window1.close()


        # Revelar contraseña
        elif event1 == 'show_password':
            password_input = window1['password']
            repite_password = window1['-password-']
            show_password = change_eye_button(show_password, password_input, repite_password, window1)

        # Este es el menu para seleecionar la contraseña random
        elif event1 == 'submenu':
            action = values1['submenu']

            if action == "Open Generator":
                # Crear GUI para modificar el generador de contraseñas
                p = GeneratorPopup()
                window1['password'].update(p)
                window1['-password-'].update(p)
                strength = setQuality(p, window1)
                del p

            elif action == "Robust":
                p = generate_random_password(24, window1,)
                strength = setQuality(p, window1)
                del p

            elif action == "Medium":
                p = generate_random_password(18, window1, values=["upper", "lower", "digits", "special", "minus", "underline"])
                strength = setQuality(p, window1)
                del p

            elif action == "Low":
                p = generate_random_password(12, window1, values=["upper", "lower", "digits"])
                strength = setQuality(p, window1)
                del p

        # Borrar entrada
        elif event1 == "delete":
            delete_sql_entry(title, id_column, used)
            window1.close()

    # Llamar a la función para hacer el dump de la base de datos
    database_new_info, new_tables = dump_database(db_file)

    window1.close()
    return database_new_info, new_tables, db_file


def check_database(db_file):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS General (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT, quality INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Wifis (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT, quality INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Windows (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT, quality INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Internet (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT, quality INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Mail (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT, quality INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Papelera (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT, quality INTEGER)''')
    conn.commit()

    # Versiones antiguas lo necesitan...f
    tables_to_check = ['General', 'Wifis', 'Windows', 'Internet', 'Mail', 'Papelera']

    for table_name in tables_to_check:
        # Verificar si la columna 'quality' existe en la tabla
        c.execute(f"PRAGMA table_info({table_name})")
        columns = c.fetchall()

        quality_column_exists = False
        for column in columns:
            if column[1] == 'quality':
                quality_column_exists = True
                break

        # Si la columna 'quality' no existe, agrégala
        if not quality_column_exists:
            c.execute(f"ALTER TABLE {table_name} ADD COLUMN quality INTEGER")

    conn.commit()
    c.close()

    c.close()


def dump_database(db_file):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = c.fetchall()
    database = {}
    real_tables = []
    for table in tables:
        print(table)
        table_name = table[0]
        real_tables.append(table_name)

        c.execute(f"SELECT * FROM {table_name}")
        rows = c.fetchall()
        table_data = []

        for row in rows:
            record = {
                'id': row[0],
                'title': row[1],
                'username': row[2],
                'password': row[3],
                'url': row[4],
                'notes': row[5],
                'quality': row[6]

            }

            table_data.append(record)
        database[table_name] = table_data

    conn.close()
    print(database)
    return database, real_tables


def create_database():
    global file
    done = False
    layout = [
        [Sg.Text('Create a new DataBase File', justification="center", pad=((2, 2),(2, 2)))],
        [Sg.Text(" ", key="-error-", text_color="red", justification="center", expand_x=True)],
        [Sg.Text("Name of the file:    "), Sg.Input("", key='name_db')],
        [Sg.Text('Master password: '), Sg.Input("", key="-master-password-", password_char="•"),

         # Boton para ver contraseña
         Sg.Button("", key="show_password", image_filename=resource_path(f'{imgPath}/eye_icon1.png'),
                   mouseover_colors="#C2FFFE", button_color=color_gris_claro, tooltip="Show / Hide", size=button_size,
                   font=button_font)],

        [Sg.Text("Again                       "),
         Sg.Input("", password_char="•", key="-masterpassword-"),

         # Boton para generar contraseña
         Sg.Button("", key="generate", image_filename=resource_path(f'{imgPath}/generate.png'),
                   mouseover_colors="#C2FFFE", button_color=color_gris_claro, tooltip="Generate", size=button_size,
                   font=button_font), ],
        [Sg.Text("Destination:           "), Sg.InputText("{}/".format(Path.home()), key='-FOLDER-', enable_events=True, visible=True)],
        [Sg.Button("Create", key="finalize_creation", size=button_size, font=button_font), Sg.Text(" " * 110),
         Sg.FolderBrowse('Browse', target='-FOLDER-', size=button_size, font=button_font)],
    ]

    show_password = False
    window = Sg.Window('Create DB', layout, icon=resource_path(f"{imgPath}/security.ico"))

    while True:
        try:
            event, values = window.read()
            print(event, values)

            # Cerrar
            if event == Sg.WIN_CLOSED:
                break

            elif (event == "finalize_creation" and values['-FOLDER-'] and values['name_db']
                  and values['-master-password-'] == values['-masterpassword-']):

                global secret_key
                secret_key = values['-master-password-']
                file = values['-FOLDER-'] + '/' + values['name_db'] + ".db"
                open(file, "w")

                check_database(file)
                shutil.copyfile(file, temp.name)
                window.close()
                done = True

            elif event == "-FOLDER-":
                continue

            elif event == 'show_password':
                password_input = window['-master-password-']
                repite_password = window['-masterpassword-']
                show_password = change_eye_button(show_password, password_input, repite_password, window)

            # Este es el menu para seleecionar la contraseña random
            elif event == 'generate':
                get_pass(32, window, master=True)

            else:
                Sg.popup("Rellena todos los campos...", title='Error...', icon=resource_path(f"{imgPath}/security.ico"))
        except FileNotFoundError:
            window['-error-'].update("Ubicacion NO encontrada...")

    window.close()
    if done:
        return temp.name
    else:
        return None


def change_eye_button(show_password, password_input, repite_password, window):
    button_show = window['show_password']

    # Ocultamos
    if show_password is True:

        password_input.update(password_char="•")
        button_show.update(image_filename=resource_path(f"{imgPath}/eye_icon1.png"))

        if repite_password:
            repite_password.update(password_char="•")
        return False


    # Mostramos
    else:
        password_input.update(password_char="", )
        button_show.update(image_filename=resource_path(f'{imgPath}/hidden1.png'))

        if repite_password:
            repite_password.update(password_char="")

        return True


def setDefDatabas(db_file):
    with open(configPath + "\\dbName", "w") as f:
        f.write(db_file)
    f.close()


def done(key, window2, values2):
    global file
    file = values2['-FILE-']
    if os.path.exists(file) and os.path.isfile(file):
        shutil.copyfile(file, temp.name)

        # Desencrtiptar el arcivo
        check = init_decrypt_file(str(temp.name), key)
        if check == 1:
            return 1
        else:
            return temp.name

    else:
        return 2


def open_database():
    global show_password
    global secret_key


    show_password = False  # Variable para almacenar la ventana emergente de submenú
    print(fileDatabaseExample)
    layout = [

        [Sg.Text('Select or the database file')],
        [Sg.Text(" ", key="-error-", text_color="red", justification="center", expand_x=True)],
        [Sg.Text("File Path                "), Sg.InputText(fileDatabaseExample ,key='-FILE-', enable_events=True,
                                                            visible=True),

        ],

        # Contraseña de desecnriptacion...
        [Sg.Text("Master Password"),
         Sg.Input("", password_char="•", key="-master-key-"),

         # Boton para ver contraseña
         Sg.Button("", key="show_password", image_filename=resource_path(f'{imgPath}/eye_icon1.png'),
                   mouseover_colors="#C2FFFE", button_color=color_gris_claro, tooltip="Show / Hide", size=button_size,
                   font=button_font)],

        [Sg.Text("_" * 65, text_color=color_gris_claro, expand_x=True, expand_y=True)],

        [Sg.Button('Create', key="create_db", size=button_size, font=button_font),
         Sg.Button("Ok", key="done", size=button_size, font=button_font), Sg.Text(" " * 93),

         # Buscador de archivos
         Sg.FileBrowse('Browse', target='-FILE-', file_types=(("Database Files", "*.db"),), size=button_size,
                      font=button_font)],

    ]

    window2 = Sg.Window('Open Database', layout, icon=resource_path(f"{imgPath}/security.ico"))


    while True:

        event2, values2 = window2.read()
        print(event2, values2)

        # Cerrar
        if event2 == Sg.WIN_CLOSED:
            window2.close()
            db_file = None
            break

        # Crear Base de Datos
        elif event2 == 'create_db':
            db_file = create_database()
            if not db_file:
                continue
            break

        # Abrir archivo
        elif event2 == "done" and values2['-FILE-'] and values2['-master-key-']:
            secret_key = values2['-master-key-']
            db_file = done(secret_key, window2, values2)

            if db_file == 1:
                window2['-error-'].update("Password NOT correct...")

            elif db_file == 2:
                window2['-error-'].update("Database Not Found...")

            else:
                break

        elif event2 == 'show_password':
            password_input = window2['-master-key-']
            repite_password = ""
            show_password = change_eye_button(show_password, password_input, repite_password, window2)

    setDefDatabas(values2['-FILE-'])
    try:
        window2.close()
        return db_file
    except UnboundLocalError:
        window2.close()
        return None

def open_db_layout(database, table):
    print(database, table)
    table_data = []

    for record in database[table]:
        id_t = record['id']
        try:
            title = record['title']
        except:
            title = ""
        try:
            user = record['username']
        except:
            user = ""
        try:
            password = record['password']
        except:
            password = ""
        try:
            url = record['url']
        except:
            url = ""
        try:
            notes = record['notes']
        except:
            notes = ""
        try:
            quality = record['quality']
        except:
            quality = ""

        table_data.append([id_t, title, user, password, url, notes, quality])

    table_data_with_asterisks = [[title, user, "*" * len(password), url, notes] for id_t, title, user, password, url, notes, quality in table_data]
    print(table_data_with_asterisks, table_data)

    headings = ['Title', 'Username', 'Password', 'URL', 'Notes']
    return table_data, headings, table_data_with_asterisks


def dump_table_data(table_name):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    c.execute(f"SELECT * FROM {table_name}")
    rows = c.fetchall()

    table_data = []

    for row in rows:
        record = {
            'id': row[0],
            'title': row[1],
            'username': row[2],
            'password': row[3],
            'url': row[4],
            'notes': row[5],
            'quality': row[6]

        }

        table_data.append(record)
    print(table_data)
    c.fetchall()

    conn.commit()
    conn.close()
    return table_data


def udpate_table_gui(table_data):
    try:
        id_t = table_data['id']
    except:
        id_t = ""
    try:
        title = table_data['title']
    except:
        title = ""
    try:
        user = table_data['username']
    except:
        user = ""
    try:
        password = table_data['password']
    except:
        password = ""
    try:
        url = table_data['url']
    except:
        url = ""
    try:
        notes = table_data['notes']
    except:
        notes = ""

    table_data_with_asterisks = [title, user, "*" * len(password), url, notes]

    if table_data_with_asterisks is None:
        return ""

    return table_data_with_asterisks


def update_db(db_file, element, table_data, table_name):
    database_new_info, new_tables, db_file = main_entry(table_name, element, db_file, table_data)
    table_data, headings, table_data_with_asterisks = open_db_layout(database_new_info, table_name)
    window['main_table'].update(values=table_data_with_asterisks)

def get_title(dbfile):
    return os.path.basename(dbfile)


def saveKey():
    tmp = tempfile.NamedTemporaryFile(delete=False); tmp.close()
    shutil.copyfile(db_file, tmp.name)
    crypt_thread = threading.Thread(target=init_crypt_file, args=(tmp.name, secret_key))
    crypt_thread.start()
    crypt_thread.join()
    shutil.copyfile(tmp.name, file)

    os.remove(tmp.name)
    return 0


def closing(err=False):
    crypt_thread = threading.Thread(target=init_crypt_file, args=(db_file, secret_key))
    crypt_thread.start()
    crypt_thread.join()
    window.close()
    if err:
        raise err
    sys.exit(0)


def checkContent():
    # Si el temp es diferente que la base de datos le decimos que tiene datos sin guardar
    tmp = tempfile.NamedTemporaryFile(delete=False); tmp.close()
    tmpDB = tempfile.NamedTemporaryFile(delete=False); tmpDB.close()
    shutil.copyfile(db_file, tmp.name)
    shutil.copyfile(file, tmpDB.name)
    crypt_thread = threading.Thread(target=init_decrypt_file, args=(tmpDB.name, secret_key))
    crypt_thread.start()
    crypt_thread.join()
    d = open(tmpDB.name, "rb").read()
    t = open(tmp.name, "rb").read()
    if d == t:
        os.remove(tmpDB.name); os.remove(tmp.name)
        del d, t
        return 0
    else:
        event = Sg.popup_ok_cancel("You need to save changes on the database. You want it?...", title="Warning", icon=resource_path(f"{imgPath}/security.ico"))
        if event == 'OK':
            saveKey()  # Llamada a la función para guardar los cambios
            os.remove(tmp.name)
            os.remove(tmpDB.name)
            return 0
        else:
            os.remove(tmp.name)
            os.remove(tmpDB.name)
            return 0


def changeImage(key, background, window):
    if background == "white":
        if "General" in key:
            window[key].update(filename=f"{imgPath}/general.png")
        elif "Internet" in key:
            window[key].update(filename=f"{imgPath}/internet.png")
        elif "Wifi" in key:
            window[key].update(filename=f"{imgPath}/wifi.png")
        elif "Windows" in key:
            window[key].update(filename=f"{imgPath}/windows.png")
        elif "Mail" in key:
            window[key].update(filename=f"{imgPath}/mail.png")
        elif "Papelera" in key:
            window[key].update(filename=f"{imgPath}/trash.png")
        else:
            pass

    else:
        if "General" in key:
            window[key].update(filename=f"{imgPath}/generalblue.png")
        elif "Internet" in key:
            window[key].update(filename=f"{imgPath}/internetblue.png")
        elif "Wifi" in key:
            window[key].update(filename=f"{imgPath}/wifiblue.png")
        elif "Windows" in key:
            window[key].update(filename=f"{imgPath}/windowsblue.png")
        elif "Mail" in key:
            window[key].update(filename=f"{imgPath}/mailblue.png")
        elif "Papelera" in key:
            window[key].update(filename=f"{imgPath}/trashblue.png")

        else:
            pass



def updateWindow(event, window, db_file):
    global default_table
    print(default_table)
    try:
        # Seleccionamos tabla
        Newtable = event
        window[event].update(background_color="#cde8ff")
        changeImage(event + "Img", "#cde8ff", window)
        window[default_table].update(background_color="white")
        changeImage(default_table + "Img", "white", window)
        database_info, tables = dump_database(db_file)

        # Sacamos datos de la tabla y le damos a la window los datos con la password ocultada
        table_data, headings, table_data_with_asterisks = open_db_layout(database_info, Newtable)

        # Actualizamos
        window['main_table'].update(values=table_data_with_asterisks)
        default_table = Newtable
        return table_data, headings, table_data_with_asterisks

    except KeyError:
        return


if __name__ == "__main__":
    try:
        checkStart()
        desktop = os.path.expanduser('~') + "\\Desktop\\"
        color_gris_claro = '#cdcdcd'
        color_gris_fondo_claro = "#f0f0f0"
        blue_color = "#CCE8FF"
        purple_color = "#EEEEFF"
        button_size = (7, 1)
        button_font = ("Popins", 7)

        # Tema personalizado
        Sg.theme_add_new('chill', {'BACKGROUND': "white",
                                   'TEXT': 'black',
                                   'INPUT': 'white',
                                   'TEXT_INPUT': 'black',
                                   'SCROLL': color_gris_claro,   # Color de la barra de movimiento del Multiline
                                   'BUTTON': ('black', color_gris_claro),
                                   'PROGRESS': ('white', color_gris_claro),
                                   'BORDER': 1,
                                   'SLIDER_DEPTH': 0,
                                   'PROGRESS_DEPTH': 0})

        Sg.set_options(font=("Poppins", 9))
        Sg.theme('chill')
        default_table = "General"
        # Select Database
        if not database_info:
            db_file = open_database()
            check_database(db_file)

            if not db_file:
                sys.exit(1)

            database_info, tables = dump_database(db_file)
            # Sublayout con datos de la base de datos
            table_data, headings, table_data_with_asterisks = open_db_layout(database_info, default_table)


        # Menu superior
        menu_definit = [['&File', ['&Open', '&Save::savekey', '---', '&Properties', 'E&xit']],
                    ['&Group', ['Add Group'], ],
                    ['&Entry', ['Copy Username', 'Copy Password', 'Edit Entry', 'Add Entry']],]

        tmoFont = ("Poppins", 9, "bold")
        list_layout = [
            [Sg.Image(source=resource_path(f"{imgPath}/generalblue.png"), pad=((4,0),(2,2)), key="GeneralImg"), Sg.Text("General", font=tmoFont, enable_events=True, background_color="#cde8ff", pad=((0,100),(2,2)), key="General", )],
            [Sg.Image(source=resource_path(f"{imgPath}/internet.png"), pad=((20,0),(2,2)), key="InternetImg"), Sg.Text("  Internet", pad=((0,0),(2,2)), font=tmoFont, enable_events=True, key="Internet")],
            [Sg.Image(source=resource_path(f"{imgPath}/wifi.png"), pad=((20,0),(2,2)), key="WifisImg"), Sg.Text("  Wifis", pad=((0,0),(2,2)), font=tmoFont, enable_events=True, key="Wifis")],
            [Sg.Image(source=resource_path(f"{imgPath}/windows.png"), pad=((20,0),(2,2)), key="WindowsImg"), Sg.Text("  Windows", pad=((0,0),(2,2)), font=tmoFont, enable_events=True, key="Windows")],
            [Sg.Image(source=resource_path(f"{imgPath}/mail.png"), pad=((20,0),(2,2)), key="MailImg"), Sg.Text("  Mail", pad=((0,0),(2,4)), font=tmoFont, enable_events=True, key="Mail")],
            [Sg.Image(source=resource_path(f"{imgPath}/trash.png"), pad=((20,0),(2,2)), key="PapeleraImg"), Sg.Text("  Papelera", pad=((0,0),(2,2)), font=tmoFont, enable_events=True, key="Papelera")],

        ]

        table_layout = [
            [Sg.Table(values=table_data_with_asterisks,
                             headings=headings,
                             max_col_width=30,
                             display_row_numbers=False,
                             num_rows=min(25, len(table_data_with_asterisks)),
                             expand_x=True,
                             border_width=0,
                             expand_y=True,
                             enable_click_events=True,
                             justification="center",
                             row_height=18,
                             selected_row_colors=("black", blue_color),
                             alternating_row_color=purple_color,
                             header_border_width=0,
                             header_relief="RELIEF_RAISED",
                             hide_vertical_scroll=True,
                             sbar_background_color=color_gris_fondo_claro,
                             header_background_color="white",
                             right_click_menu=right_option_click,
                             key="main_table")
            ]
        ]



        layout = ([
            # Menu superior
            [Sg.Menu(menu_definit)],


            # Sección izquierda de la pantalla
            [Sg.Frame(title="", layout=list_layout, size=(250, 1440), key="tables"),

            # Sección derecha de la pantalla
            Sg.Frame(title="", layout=table_layout, size=(4000,1440))],


            #[Sg.Frame(title="Previsualization", layout=prev_layout, size=(500, 340), key="prev"),]

        ],)


        title = get_title(file)
        # Ventana principal
        window = Sg.Window(title, layout, resizable=True, size=(900, 800), icon=resource_path(f"{imgPath}/security.ico"))

        while True:
            event, values = window.read()
            print(event, values)

            # Cerrar con la X
            if event in (Sg.WIN_CLOSED, "Exit"):
                if checkContent() != 0:
                    continue
                else:
                    break

            # update de la tabla "main_table"
            elif event == "Open":
                db_file = open_database()

                if db_file is None:
                    continue

                database_info, tables = dump_database(db_file)

                # Sublayout con datos de la base de datos
                table_data, headings, table_data_with_asterisks = open_db_layout(database_info, default_table)

                # Actualizar secciones...
                window.set_title(get_title(file))
                window['main_table'].update(values=table_data_with_asterisks)


            elif event == "Add Entry":
                database_new_info, new_tables, db_file = main_entry(default_table, [], db_file, table_data)

                print("\n", database_new_info, new_tables, db_file, "\n\n\n")

                table_data, headings, table_data_with_asterisks = open_db_layout(database_new_info, default_table)
                window['main_table'].update(values=table_data_with_asterisks)

            elif event in ['General', 'Internet', 'Wifis', "Windows", "Mail", "Papelera"]:
                table_data, headings, table_data_with_asterisks = updateWindow(event, window, db_file)

            elif event == "Save::savekey":
                saveKey()
                Sg.popup_ok("Database Has been saved... ", icon=resource_path(f"{imgPath}/security.ico"))

            elif values['main_table']:
                try:
                    x, y = event[2]

                    element = table_data[x]

                    # Updating all
                    update_db(db_file, element, table_data, default_table)

                except ValueError:
                    continue

                except TypeError:
                    continue


        closing()

    except Exception as e:
        print("\n\n\n\n", e, "\n\n\n\n")
        closing(e)

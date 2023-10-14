import filecmp
import os
import pathlib
import shutil
import sys
import tempfile
from pathlib import Path
from pprint import pprint
import PySimpleGUI as Sg
import sqlite3
import string
import random
import threading
import secrets
from secure_data.cryptor import init_decrypt_file, init_crypt_file

# Encrypt Decrypt hecho!
# Diseñar la app para que sea bonita : )
# Borrar logica, acabar


options = ['unused', ['Open Generator', '---', 'Robust', 'Medium', 'Low']]
right_option_click = ['unused', ['Add Entry', '---', 'Edit Entry', 'Copy Username', 'Copy Password']]
#temp = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
#temp = "C:\\Users\\pablo_c\\AppData\\Local\\Temp\\tmp0za2_rl8.db"
temp = tempfile.NamedTemporaryFile(delete=False)
temp.close()

action = False

# Config Files
path = str(pathlib.Path.home()) + "\\SecurEntry"
configPath = path + "\\data"


def checkStart():
    if not os.path.exists(path):
        os.makedirs(path)
    if not os.path.exists(configPath):
        os.makedirs(configPath)


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return str(os.path.join(base_path, relative_path))


def get_pass(lenght, window1, master=False):
    passwrd = rndom_passwrd(int(lenght))
    if master:
        window1['-master-password-'].update(passwrd)
        window1['-masterpassword-'].update(passwrd)
    else:
        window1['password'].update(passwrd)
        window1['-password-'].update(passwrd)


def rndom_passwrd(index):
    all_chars = list(string.ascii_lowercase) + list(string.ascii_uppercase) + list(string.digits) + list(string.punctuation)
    passwrd = "".join(random.choice(all_chars) for _ in range(index))
    return passwrd


def write_password(password, user, title, url, used, notes, tables_info):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    id_t = len(tables_info)

    query = "INSERT INTO {} (id, title, username, password, url, notes) VALUES (?, ?, ?, ?, ?, ?)".format(used)
    values = (id_t, title, user, password, url, notes)
    c.execute(query, values)

    conn.commit()
    conn.close()


def update_password(password, user, title, url, used, notes, id_t):
    try:

        conn = sqlite3.connect(db_file)
        c = conn.cursor()

        # Buscar la entrada existente en la tabla y actualizarla
        query = f"UPDATE {used} SET password=?, username=?, title=?, url=?, notes=? WHERE id=?"
        values = (password, user, title, url, notes, id_t)

        c.execute(query, values)

        conn.commit()
        conn.close()

        return True

    except Exception:
        return False


def generate_random_password(lenght, window1):
    get_pass(lenght, window1)
    window.finalize()


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




def main_entry(used, entry_data, db_file, tables_info):
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
    Sg.theme('chill')
    options = ['unused', ['Open Generator', '---', 'Robust', 'Medium', 'Low']]


    default_title = "Add Entry"

    # lo que se muestra:
    layout = [[
        Sg.Image(resource_path('images/1.png'), key="image1"),
        Sg.T('SAVE PASSWORD ', text_color='red', justification="center", pad=((2, 2), (4, 4)), font=("Arial", 12))],
        [Sg.Text(' ' * 60)],

        # Titulo de la contraseña
        [Sg.Text("Titulo:             "), Sg.Input(title, key="title", size=(45, 1))],
        # Usuario
        [Sg.Text("User name:  "), Sg.Input(user, key='user', size=(45, 1))],

        # Contraseña
        [Sg.Text("Password:    "), Sg.Input(password, key='password', password_char='•', size=(40, 1)),
         # Mostramos o ocultamos la contrasela
         Sg.Button("", key="show_password", image_filename=resource_path('images/eye_icon1.png'),
                   mouseover_colors="#C2FFFE", button_color=color_gris_claro, tooltip="Show / Hide", size=button_size,
                   font=button_font), ],

        # Confirmacion de contraseña
        [Sg.Text("Repeat:         "), Sg.Input(password, key='-password-', password_char='•', size=(40, 1)),
         # Generador de contraselas
         Sg.ButtonMenu('', options, key='submenu', button_color=color_gris_claro,
                       image_filename=resource_path("images/generate.png"), tooltip="Generator", pad=(1, 0),)],

        # URL
        [Sg.Text("URL:              "), Sg.Input(url, key='url', size=(45, 1))],

        # Comentarios o notas
        [Sg.Text("Notes:           "),
         Sg.Multiline(notes, size=(45, 10), key='notes', border_width=2), ],

        # Separacion para los botones...
        [Sg.Text("_" * 60, text_color="gray", pad=(0, 0), expand_x=True, expand_y=True)],

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
    window1 = Sg.Window(default_title, layout, border_depth=2)

    while True:
        event1, values1 = window1.read()
        print(event1, values1)

        # Cerrar con la X
        if event1 == Sg.WIN_CLOSED:
            break


        # Generar contraseña random
        elif event1 == 'cancel':
            break

        # Guardar y continuar
        elif event1 == "accept":
            # No coinciden...
            if values1['password'] != values1['-password-']:
                Sg.popup("Contraseñas NO coninciden...",
                         title="Passwords doesn't match")

            # Contraseña VACIA
            elif values1['password'] == "":
                Sg.popup("No has introducido una contraseña. \n\nRecuerda que puedes generar una cuando lo necesites",
                         title='Empty Password')

            # Guardamos y cerramos...
            else:
                # valores para la contraseña
                title_l = values1['title']
                password_l = values1['password']
                user_l = values1['user']
                url_l = values1['url']
                notes_l = values1['notes']

                if entry_data:
                    update_password(password_l, user_l, title_l, url_l, used, notes_l, id_column)
                    window1.close()

                else:
                    write_password(password_l, user_l, title_l, url_l, used, notes_l, tables_info)
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
                continue

            elif action == "Robust":
                generate_random_password(20, window1)

            elif action == "Medium":
                generate_random_password(14, window1)

            elif action == "Low":
                generate_random_password(8, window1)

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

    c.execute('''CREATE TABLE IF NOT EXISTS General (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Wifis (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Windows (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Internet (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Mail (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS Papelera (id INTEGER, title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT)''')

    conn.commit()
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
                'notes': row[5]

            }

            table_data.append(record)
        database[table_name] = table_data

    conn.close()
    pprint(database)
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
         Sg.Button("", key="show_password", image_filename=resource_path('images/eye_icon1.png'),
                   mouseover_colors="#C2FFFE", button_color=color_gris_claro, tooltip="Show / Hide", size=button_size,
                   font=button_font)],

        [Sg.Text("Again                       "),
         Sg.Input("", password_char="•", key="-masterpassword-"),

         # Boton para generar contraseña
         Sg.Button("", key="generate", image_filename=resource_path('images/generate.png'),
                   mouseover_colors="#C2FFFE", button_color=color_gris_claro, tooltip="Generate", size=button_size,
                   font=button_font), ],
        [Sg.Text("Destination:           "), Sg.InputText("{}/".format(Path.home()), key='-FOLDER-', enable_events=True, visible=True)],
        [Sg.Button("Create", key="finalize_creation", size=button_size, font=button_font), Sg.Text(" " * 110),
         Sg.FolderBrowse('Browse', target='-FOLDER-', size=button_size, font=button_font)],
    ]

    show_password = False
    window = Sg.Window('Create DB', layout)

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
                get_pass(25, window, master=True)

            else:
                Sg.popup("Rellena todos los campos...", title='Error...')
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
        button_show.update(image_filename=resource_path("images/eye_icon1.png"))

        if repite_password:
            repite_password.update(password_char="•")
        return False


    # Mostramos
    else:
        password_input.update(password_char="", )
        button_show.update(image_filename=resource_path('images/hidden1.png'))

        if repite_password:
            repite_password.update(password_char="")

        return True


def done(key, window2, values2):
    global file
    file = values2['-FILE-']
    if os.path.exists(file):
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

    layout = [

        [Sg.Text('Select or the database file')],
        [Sg.Text(" ", key="-error-", text_color="red", justification="center", expand_x=True)],
        [Sg.Text("File Path                "), Sg.InputText("{}".format(Path.home()),key='-FILE-', enable_events=True,
                                                            visible=True),

        ],

        # Contraseña de desecnriptacion...
        [Sg.Text("Master Password"),
         Sg.Input("", password_char="•", key="-master-key-"),

         # Boton para ver contraseña
         Sg.Button("", key="show_password", image_filename=resource_path('images/eye_icon1.png'),
                   mouseover_colors="#C2FFFE", button_color=color_gris_claro, tooltip="Show / Hide", size=button_size,
                   font=button_font)],

        [Sg.Text("_" * 65, text_color=color_gris_claro, expand_x=True, expand_y=True)],

        [Sg.Button('Create', key="create_db", size=button_size, font=button_font),
         Sg.Button("Ok", key="done", size=button_size, font=button_font), Sg.Text(" " * 93),

         # Buscador de archivos
         Sg.FileBrowse('Browse', target='-FILE-', file_types=(("Database Files", "*.db"),), size=button_size,
                      font=button_font)],

    ]

    window2 = Sg.Window('Open Database', layout)


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

        table_data.append([id_t, title, user, password, url, notes])

    table_data_with_asterisks = [[title, user, "*" * len(password), url, notes] for id_t, title, user, password, url, notes in table_data]

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
            'notes': row[5]

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
    """separators = ['//', '/', '\\\\',  '\\']
    for sep in separators:
        parts = db_file.split(sep)
        if len(parts) > 1:
            return parts[3]"""
    return os.path.basename(dbfile)


def saveKey():
    tmp = tempfile.NamedTemporaryFile(delete=False); tmp.close()
    shutil.copyfile(db_file, tmp.name)
    crypt_thread = threading.Thread(target=init_crypt_file, args=(tmp.name, secret_key))
    crypt_thread.start()
    crypt_thread.join()
    shutil.copyfile(tmp.name, file)
    return 0

def closing():
    print("Closing")
    crypt_thread = threading.Thread(target=init_crypt_file, args=(db_file, secret_key))
    crypt_thread.start()
    crypt_thread.join()
    window.close()

def checkContent():
    # Si el temp es diferente que la base de datos le decimos que tiene datos sin guardar
    tmp = tempfile.NamedTemporaryFile(delete=False); tmp.close()
    shutil.copyfile(db_file, tmp.name)
    crypt_thread = threading.Thread(target=init_crypt_file, args=(tmp.name, secret_key))
    crypt_thread.start()
    crypt_thread.join()
    if filecmp.cmp(db_file, tmp.name): return 0
    else: saveKey(); Sg.popup("The Database has been saved. You have changes unsaved....", title="Warning", )
    return 1



if __name__ == "__main__":
    try:
        checkStart()
        database = {}
        desktop = os.path.expanduser('~') + "\\Desktop\\"
        color_gris_claro = '#cdcdcd'
        color_gris_fondo_claro = "#f0f0f0"
        blue_color = "#D3E7FF"
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
        if not database:
            db_file = open_database()

            if not db_file:
                exit(0)

            database_info, tables = dump_database(db_file)
            # Sublayout con datos de la base de datos
            table_data, headings, table_data_with_asterisks = open_db_layout(database_info, default_table)


        # Menu superior
        menu_definit = [['&File', ['&Open', '&Save::savekey', '---', '&Properties', 'E&xit']],
                    ['&Group', ['Add Group'], ],
                    ['&Entry', ['Copy Username', 'Copy Password', 'Edit Entry', 'Add Entry']],]

        # Parte izquierda (grupos de la base de datos
        """sidebar_layout = [
            [Sg.Text('CONTRASEÑAS\n\n\n', text_color="black", font="Origen")],
            [Sg.Button('General', key="change-general", size=button_size, font=button_font, mouseover_colors="#cde8ff"),]],"""

        list_layout = [
            [Sg.Listbox(['General', 'Internet', 'Wifis', "Windows", "Mail", "Papelera"], no_scrollbar=True
                        ,s=(300,540), enable_events=True,
                        highlight_background_color="#cde8ff", highlight_text_color="black", pad=(2, 2))],
            [Sg.HSeparator()],
            [Sg.Text("Previsualization", key="entry-data")]
        ]

        layout = [
            # Menu superior
            [Sg.Menu(menu_definit)],

            # Sección izquierda de la pantalla
            [Sg.Frame(title="", layout=list_layout, size=(300, 1440), key="tables"),

            # Linea que separa las dos secciones
            Sg.VSeperator(),

            # Sección derecha de la pantalla
            Sg.Table(values=table_data_with_asterisks,
                     headings=headings,
                     max_col_width=30,
                     auto_size_columns=True,
                     display_row_numbers=False,
                     num_rows=min(25, len(table_data_with_asterisks)),
                     expand_x=True,
                     expand_y=True,
                     enable_click_events=True,
                     justification="center",
                     row_height=25,  # Ajusta el valor según tu preferencia para la separación
                     selected_row_colors=("black", blue_color),
                     alternating_row_color=purple_color,
                     header_border_width=1,
                     sbar_background_color=color_gris_fondo_claro,
                     header_background_color=color_gris_fondo_claro,
                     right_click_menu=right_option_click,
                     key="main_table")],

        ]

        title = get_title(file)
        # Ventana principal
        window = Sg.Window(title, layout, resizable=True, size=(1920, 1080))


        while True:
            event, values = window.read()
            print(event, values)

            # Cerrar con la X
            if event == Sg.WIN_CLOSED or event == "Exit":
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

            elif event == 1:
                try:
                    # Seleccionamos tabla
                    default_table = values[1][0]
                    database_info, tables = dump_database(db_file)

                    # Sacamos datos de la tabla y le damos a la window los datos con la password ocultada
                    table_data, headings, table_data_with_asterisks = open_db_layout(database_info, default_table)

                    # Actualizamos
                    window['main_table'].update(values=table_data_with_asterisks)

                except KeyError:
                    continue

            elif event == "Save::savekey":
                saveKey()

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
        exit(0)

    except Exception as e:
        print("\n\n\n\n", e, "\n\n\n\n")
        closing()
        exit(0)
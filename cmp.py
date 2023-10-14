import os

# Ruta al directorio de imágenes
image_dir = 'images'

# Genera la parte --add-data del comando para cada archivo en el directorio de imágenes
add_data_parts = [f'--add-data "{os.path.join(image_dir, filename)};images/."' for filename in os.listdir(image_dir)]

# Une todas las partes en una sola cadena
add_data_option = ' '.join(add_data_parts)

# Ahora puedes usar add_data_option en tu comando pyinstaller
command = f'pyinstaller --onefile --noconsole --clean --strip --noupx --icon="images\shield.ico" {add_data_option} -n SecurEntry manager.py'
print(command)
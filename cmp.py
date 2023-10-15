import os
import subprocess

def makeCommand():
    image_dir = 'src/images'
    # Genera la parte --add-data del comando para cada archivo en el directorio de imágenes
    add_data_parts = [f'--add-data "{os.path.join(image_dir, filename)};images/."' for filename in os.listdir(image_dir)]
    add_data_option = ' '.join(add_data_parts)
    return f'pyinstaller --onefile --noconsole --clean --strip --noupx --icon="src\images\shield.ico" {add_data_option} -n SecurEntry src/manager.py'


def execCommand(command):
    cmpl = subprocess.Popen(command, shell=True)
    cmpl.wait()


def main():
    command = makeCommand()
    print("\n\tExecuting command to compile: %s\n\n" % command)
    execCommand(command)


if __name__ == "__main__":
    main()

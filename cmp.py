import os
import shutil
import subprocess

def makeCommand():
    global aux
    image_dir = 'src/images'
    # Genera la parte --add-data del comando para cada archivo en el directorio de imágenes
    add_data_parts = [f'--add-data "{os.path.join(image_dir, filename)};images/."' for filename in os.listdir(image_dir)] # PyInstaller
    add_data_option = ' '.join(add_data_parts)
    aux = f'pyinstaller --onefile --noconsole --clean --noupx --icon="src\images\security.ico" {add_data_option} -n SecurEntry src/manager.py'  # PyInstaller
    return f'pyinstaller --onefile --noconsole --key="Secur/EntryV1" --clean --strip --noupx --icon="src\images\security.ico" {add_data_option} -n SecurEntry src/manager.py' # PyInstaller
    # add_data_parts = [f' --include-data-file="{os.path.join(image_dir, filename)}=images/{filename}"' for filename in os.listdir(image_dir)]   # Nuitka
    #return f'nuitka --exe --onefile --standalone --disable-console --windows-icon-from-ico="src\images\security.ico" {add_data_option} --enable-plugin=tk-inter --output-dir="./dist" --output-filename="SecurEntry" src/manager.py'  # Nuitka


def execCommand(command):
    cmpl = subprocess.Popen(command, shell=True)
    cmpl.wait()


def main():
    command = makeCommand()
    print("\nExecuting command to compile: %s\n\n" % command)
    execCommand(command)
    if not os.path.exists("./dist/SecurEntry.exe"):
        print("\n\nExecuting auxiliar command to compile: %s\n\n" % aux)
        execCommand(aux)
        

if __name__ == "__main__":
    if os.path.exists("./dist"): shutil.rmtree("./dist") ;os.makedirs("./dist")
    else: os.makedirs("./dist")
    main()

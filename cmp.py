import subprocess
import os, sysconfig, sys

#windres images/icon.rc -O coff -o icon.o

def transformC():
    commandWin = "python -m cython --embed -o src/SecurEntry.c src/manager.py"
    os.system(commandWin)
    WindowsCompilation()


def WindowsCompilation():
    if os.path.exists("src/SecurEntry.c"):
        # Variables para el comando windows
        libsPath = os.path.join(sysconfig.get_path('data'), 'libs')
        includePath = sysconfig.get_path('include')
        pythonV = ".".join(map(str, sys.version_info[:2])).replace(".", "")

        # Comando formado
        formedPowerShellCommand = f"gcc -mwindows -municode -DMS_WIN64 src/SecurEntry.c -o src/SecurEntry.exe -L{libsPath} -I{includePath} -lpython{pythonV} src/images/icon.o"

        print("\n\nExecuting command to compile: ", formedPowerShellCommand)

        cmp = subprocess.Popen(formedPowerShellCommand, shell=True)
        cmp.wait()

        print(f"\n\nCompilation was done, check for ./src/SecurEntry.exe")

    else:
        print("\n\nC module not found... try to install cython (pip install cython) or execute this command:\n\tpython -m cython --embed -o client/connection.c client/connectionC.py")


def setParameters():
    global name, icon
    input("\nEste Script solo funcionará si tienes todas las dependencias necesarias para compila el código C.\n\t\t CTRL + C to Exit | ENTER to Continue")
    transformC()


if __name__ == "__main__":
    try:
        setParameters()
    except KeyboardInterrupt:
        exit(0)

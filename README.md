This code implements the ElGamal algorithm for better performance using small numbers for encrypting and signing the message.

I compile this code using CLion, which uses the gcc compiler under the hood.
Additionally, I use OpenSSL and Boost.
Before using Boost, I installed it on my PC via Chocolatey. You can find it on their official site: https://www.boost.org/users/download/
The same story with OpenSSL: https://www.openssl.org/source/

You can install CLion and start it here or you can do it this way:
Before all you have to install CMake and g++.
And after:

Create a build directory:

Open a terminal and navigate to the root directory of your project.

Create a build directory (e.g., build):

mkdir build
Navigate to the build directory and run CMake:

Change into the newly created build directory:

cd build
Run CMake, specifying the path to the directory containing your source code:

cmake ..
This will generate project files in the build directory.

Run make:

After a successful CMake run, execute make:

make
This will build your project. If you're using g++, it will create the executable file (or files) in the build directory.

Run the program:

After building, navigate back to the root directory of your project:

cd ..
Run your program:

./build/MyExecutable

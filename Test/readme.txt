Setup gtest
	1. Install GTEST and lcov
		a. sudo apt-get install google-mock
		b. cd /usr/src/gmock
		c. Sudo mkdir build
		d. Cd build
		e. Sudo cmake ..
		f. Sudo make
		g. sudo cp *.a /usr/lib
		h. Cd gtest
		i. sudo cp *.a /usr/lib
		j. sudo apt-get install lcov
	2. Add your tests to Test/%LibName%/Test.cpp
	3. Add cmake file to Test/%LibName%/ and add your folder to Test/CmakeList sub directories
	4. run run_ult.sh script **OR** do the following manually:
		4.1. Compile TEST
			a. cd Test
			b. mkdir build
			c. cd build
			d. cmake ..
			e. make
		4.2. (optional for code coverage) zero old code coverage results: lcov -d ./ -z
		4.3. Run TEST
		4.4. (optional for code coverage) capture code coverage results: lcov -b . -d . -c -o <output_file.info>
		4.5. (optional for code coverage) generatae html code coverage results: genhtml <output_file.info>
		5.6. code coverage report will be in index.html
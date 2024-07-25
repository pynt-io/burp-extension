# burp-extension

### How to compile the extention
1. Clone the repository
2. Install Java
3. Install Jython
4. Install Burp Suite
5. Open the project in your IDE
6. Run the following command to compile the extention
``` jython -m compileall BurpExtender.py ```
7. Run the following command to create the jar file
``` jar cfm burp-extender.jar META-INF/MANIFEST.MF BurpExtender\$py.class ```




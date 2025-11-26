# 🖥️ Project: dynip-sever

Project dynip-server is an example java Servlet to demonstrate the use of asymmetric RSA keys.

This program works in concert with dynip-client and dynip-query.

You can use a browser to query dynip-server as follows:

Set host, port and protocol as appropriate.
    
```
<protocol>://<hostname>:<port>/ipserver/server/ip/query
```
    
e.g.
    
```
https://localhost/ipserver/server/ip/query
```
or
```
http://localhost:8080/ipserver/server/ip/query
```
        
## 📖 Usage

### 1️⃣ Pre-requisites:

#### Software:
    
```text
Java 1.9.  
Gradle 8.0.2.   
Openssl 3.0.2.
Tomcat 9.0.71 and 9.0.73.
Apache http components 5.2.1.
Linux (Ubuntu 22.04.2 LTS (Jammy Jellyfish)).
```

#### Links:
    
```text
https://mvnrepository.com/artifact/org.apache.httpcomponents.client5/httpclient5 .
```
    
#### Environment:
    
```text
$projectDir must be correctly set - watch for spaces !!!
```
    
### 2️⃣ Build:

Navigate to project home directory and execute the following commands

```bash
cd $projectDir
./gradlew clean
./gradlew build
./gradlew javadoc
```

The build creates a jar located at $projectDir/build/libs/dynip-client.jar

### 3️⃣ Run in Tomcat:

Deploy build jar/war or files to tomcat webapps/IpServer directory.
    
Place private server key in tomcat at WEB-INF/server-private.key.
    
Add the **following Xml** before the closing Host tag in the servers $CATALINA_BASE/conf/server.xml file.
    
```text
<Context docBase="ipserver" path="/ipserver" reloadable="true" />
```
    
## 🔐 Credentials

### 1. Credentials File:

The credentials are sent by clients on each Post set and get endpoint.

The credentials are NOT used by the server yet - NYI.

See client dynip-client for information on how to,
    
  1. generate keys using openssl.
    
  2. encrypt and decrypt using keys manually.

package cc.tools.dynip.server;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import java.net.*;
import java.util.logging.*;
import java.util.regex.Pattern;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.crypto.*;

import static java.util.Map.entry;

/**
 * This class implements a dynamic {@link javax.servlet.Servlet} service for
 * managing Ip addresses. This program is used in conjunction with dynip-client
 * and dynip-query. This program demonstrates asymmetric key usage. This class
 * extends {@link javax.servlet.http.HttpServlet}.
 * 
 * @author cc
 * @version %I%, %G%
 * @since 0.1
 */
public final class IpServer extends HttpServlet {
	/**
	 * Auto-generated serialization ID.
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor for {@link IpServer}
	 */
	public IpServer() {
		super();
	}

	/**
	 * Method performs {@link javax.servlet.http.HttpServlet} initialization. This
	 * method overrides {@link javax.servlet.http.HttpServlet} method
	 * {@link javax.servlet.GenericServlet#init(ServletConfig)}.
	 * 
	 * @param config {@link javax.servlet.ServletConfig} provided by
	 *               {@link javax.servlet.http.HttpServlet} container.
	 * @throws ServletException .
	 */
	public void init(ServletConfig config) throws ServletException {
		super.init(config);

		try {
			KeyFactory keyFactory = KeyFactory.getInstance(CONSTANT_KEY_ALGORITHM_RSA);
			if (keyFactory == null) {
				logSevereMessageToServerLog("KeyFactory could not be created.");
				return;
			}
			_keyFactory = keyFactory;
		} catch (NoSuchAlgorithmException e) {
			logExceptionToServerLog(e);
			return;
		}

		try {
			if (!getKeyServerPrivate()) {
				logSevereMessageToServerLog("Could not init server private key.");
				return;
			}
			if (!getKeyServerPublic()) {
				logSevereMessageToServerLog("Could not init server public key.");
				return;
			}
			if (!getUserPasswordCredentials()) {
				logSevereMessageToServerLog("Could not init server public key.");
				return;
			}
		} catch (Exception e) {
			logExceptionToServerLog(e);
			return;
		}

		_isValid = true;
	}

	/**
	 * Method to obtain server's {@link java.security.PublicKey} 
	 * @return server's {@link java.security.PublicKey} value.
	 */
	public PublicKey getPubllcKey() {
		
		return _serverPublicKey;
	}

	/**
	 * Method implements this {@link javax.servlet.http.HttpServlet} handler for Get
	 * requests. This method overrides {@link javax.servlet.http.HttpServlet} method
	 * {@link javax.servlet.http.HttpServlet#doGet(HttpServletRequest, HttpServletResponse)}.
	 * 
	 * @param request  client http call
	 *                 {@link javax.servlet.http.HttpServletRequest} object.
	 * @param response client http call
	 *                 {@link javax.servlet.http.HttpServletResponse} object.
	 * @throws IOException      .
	 * @throws ServletException .
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		StringBuilder buffer1 = new StringBuilder();
		String clientIp = request.getRemoteAddr();

		response.setStatus(HttpURLConnection.HTTP_OK);
		if (isEndpointQuery(request.getRequestURI())) {
			Set<String> validClientIps = new HashSet<String>();
			if (getValidClientIpsForClient(clientIp, validClientIps)) {

				StringBuilder buffer2 = new StringBuilder();
				buffer2.append(getIpStringFromCollection(validClientIps.iterator()));
				if (isIpLocalhost(clientIp)) {
					if (!buffer2.isEmpty()) {
						buffer2.append(',');
					}
					buffer2.append(CONSTANT_LOCALHOST_IPV4_STRING);
					buffer2.append(',');
					buffer2.append(CONSTANT_LOCALHOST_IPV6_STRING);
				}
				response.getWriter().append(buffer2.toString());

				buffer1.append("doGet Get OK '");
				buffer1.append(buffer2.toString());
				buffer1.append("' to client ");
				buffer1.append(clientIp);
				logInfoMessageToServerLog(buffer1.toString());
			} else {
				buffer1.append("doGet Get NOT ok permission client ");
				buffer1.append(clientIp);
				logSevereMessageToServerLog(buffer1.toString());
			}
		} else if (isEndpointCertificate(request.getRequestURI())) { 			
			buffer1.append("doGet Certificate OK endpoint client ");
			buffer1.append(clientIp);
			logSevereMessageToServerLog(buffer1.toString() + " - " + clientIp);
			
			response.getWriter().append(this._serverPublicKeyBase64);
	    } else {
			buffer1.append("doGet Get NOT ok endpoint client ");
			buffer1.append(clientIp);
			logSevereMessageToServerLog(buffer1.toString() + " - " + clientIp);
		}
	}

	/**
	 * Method implements this {@link javax.servlet.http.HttpServlet} handler for
	 * Post requests. This method overrides {@link javax.servlet.http.HttpServlet}
	 * method
	 * {@link javax.servlet.http.HttpServlet#doPost(HttpServletRequest, HttpServletResponse)}.
	 * 
	 * @param request  client http call
	 *                 {@link javax.servlet.http.HttpServletRequest} object.
	 * @param response client http call
	 *                 {@link javax.servlet.http.HttpServletResponse} object.
	 * @throws IOException      .
	 * @throws ServletException .
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		String requestURI = request.getRequestURI();
		String clientIp = request.getRemoteAddr();

		if (isEndpointGet(requestURI)) {
			if (doPostEndpointGet(request, response)) {
				logInfoMessageToServerLog("doPost Get OK client " + clientIp);
			} else {
				logSevereMessageToServerLog("doPost Get NOT ok client " + clientIp);
			}
			return;
		}

		if (isEndpointSet(requestURI)) {
			if (doPostEndpointSet(request, response)) {
				logInfoMessageToServerLog("doPost Set OK client " + clientIp);
			} else {
				logSevereMessageToServerLog("doPost Set NOT ok client " + clientIp);
			}
			return;
		}

		if (isEndpointQuery(requestURI)) {
			if (doPostEndpointQuery(request, response)) {
				logInfoMessageToServerLog("doPost Query OK client " + clientIp);
			} else {
				logSevereMessageToServerLog("doPost Query NOT ok client " + clientIp);
			}
			return;
		}

		response.setStatus(HttpURLConnection.HTTP_OK);
		StringBuilder buffer = new StringBuilder();
		buffer.append("POST NOT ok URI '");
		buffer.append(requestURI);
		buffer.append("' from client ");
		buffer.append(clientIp);
		logSevereMessageToServerLog(buffer.toString());
	}

	/**
	 * Override of 'service' {@link javax.servlet.http.HttpServlet} life cycle
	 * method
	 * {@link javax.servlet.http.HttpServlet#service(HttpServletRequest, HttpServletResponse)}.
	 * This method returns code {@value HttpURLConnection#HTTP_INTERNAL_ERROR} to
	 * clients if {@link IpServer#_isValid} is false. Otherwise it calls the
	 * overridden method.
	 * 
	 * @param request  client {@link javax.servlet.http.HttpServletRequest} object.
	 * @param response client {@link javax.servlet.http.HttpServletResponse} object.
	 * @throws IOException      .
	 * @throws ServletException .
	 */
	protected void service(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		if (!_isValid) {
			response.setStatus(HttpURLConnection.HTTP_INTERNAL_ERROR);
			logSevereMessageToServerLogAndRespond(response, "servlet invalid.");
			return;
		}
		super.service(request, response);
	}

	/**
	 * Method adds the ip in parameter clientIp to the internal list of valid client
	 * ids {@link _validClientIps}.
	 * 
	 * @param ip contains client ip address to be added to valid ip list
	 *           {@link _validClientIps}.
	 * @return boolean if client ip was added successfully, false otherwise.
	 */
	private boolean addIpToValidIps(String ip) {
		long now = Instant.now().toEpochMilli();
		if (!isIpLocalhost(ip)) {
			synchronized (_validClientIps) {
				_validClientIps.put(ip, now + IpServer.CONSTANT_TIME_TOTAL_MS_IN_DAY);
			}
		}
		return true;
	}

	/**
	 * Method checks user and password. This is only to prevent spam and is far from 
	 * sophisticated or being fit for purpose. 
	 * @param user user name to be checked
	 * @param password user password to be checked
	 * @return true if authorised, false otherwise.
	 */
	private boolean checkUserPassword(String user, String password) {
		return user.compareTo(_user) == 0 &&
				password.compareTo(_password) == 0; 		
	}

	/**
	 * Performs decryption of encryptedData parameter and returns plain-text.
	 * 
	 * @param privateKey    key to be used to decrypt.
	 * @param encryptedData encrypted base64 data to be decrypted.
	 * @return String containing plain text result of decryption if success, else
	 *         null.
	 */
	private String decryptData(PrivateKey privateKey, String encryptedData) {
		try {
			final Cipher cipher = Cipher.getInstance(CONSTANT_CYPHER_TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)));
		} catch (Exception exception) {
			logExceptionToServerLog(exception);
		}

		return null;
	}

	/**
	 * Method implements processing for Post Get endpoint. This method bounces the
	 * client's header and ip back to the client. This checks that the client
	 * user/password are valid.
	 * 
	 * @param request  client {@link javax.servlet.http.HttpServletRequest} object.
	 * @param response client {@link javax.servlet.http.HttpServletResponse} object.
	 * @return boolean true indicating success, false otherwise.
	 * @throws IOException      .
	 * @throws ServletException .
	 */
	private boolean doPostEndpointGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		if (!isFieldListInRequest(CONSTANT_HTTP_KEYS_POST_GET, request)) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "request missing fields.");
			return false;
		}

		Map<String, StringBuilder> values = new HashMap<String, StringBuilder>();
		values.putAll(Map.ofEntries(entry(CONSTANT_HTTP_KEY_USER, new StringBuilder()),
                                entry(CONSTANT_HTTP_KEY_PASSWORD, new StringBuilder()),
                                entry(CONSTANT_HTTP_KEY_HEADER, new StringBuilder()),
				entry(CONSTANT_HTTP_KEY_TOTAL, new StringBuilder())));

		if (!getFieldValuesFromRequest(request, values) || !isNumber(values, CONSTANT_HTTP_KEY_TOTAL)) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "request bad field data.");
			return false;
		}

		if (CONSTANT_HTTP_KEY_TOTAL_MAX < Integer.parseInt(values.get(CONSTANT_HTTP_KEY_TOTAL).toString())) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "key has too many parts.");
			return false;
		}

		values.put(CONSTANT_HTTP_KEY_PART_N, new StringBuilder());
		if (!getFieldCompoundValueFromRequest(request, CONSTANT_HTTP_KEY_PART_N,
				Integer.parseInt(values.get(CONSTANT_HTTP_KEY_TOTAL).toString()),
				values.get(CONSTANT_HTTP_KEY_PART_N))) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "request bad compound field data.");
			return false;
		}

		PublicKey clientPublicKey = getKeyClientPublic(values.get(CONSTANT_HTTP_KEY_PART_N).toString());
		if (clientPublicKey == null) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "client key is bad.");
			return false;
		}

		String user = values.get(CONSTANT_HTTP_KEY_USER).toString();
		String password = values.get(CONSTANT_HTTP_KEY_PASSWORD).toString();
		
		if (!checkUserPassword(user, password)) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "client user/password are bad.");
			return false;			
		}

		Map<String, String> data = new HashMap<String, String>();
		data.put(CONSTANT_HTTP_KEY_HEADER,
				encryptData(clientPublicKey, values.get(CONSTANT_HTTP_KEY_HEADER).toString()));
		data.put(CONSTANT_HTTP_KEY_PUBLIC_IP, encryptData(clientPublicKey, request.getRemoteAddr()));

		String encodedData = encodeData(data);
		if (encodedData == null || encodedData.isBlank()) {
			response.setStatus(HttpURLConnection.HTTP_INTERNAL_ERROR);
			logSevereMessageToServerLogAndRespond(response, "could not encode data.");
			return false;
		}

		response.setStatus(HttpURLConnection.HTTP_OK);
		response.getWriter().append(encodedData);
		return true;
	}

	/**
	 * Method implements processing for Post Query endpoint. This method returns
	 * list of stored valid clients if caller has permission.
	 * 
	 * @param request  client {@link javax.servlet.http.HttpServletRequest} object.
	 * @param response client {@link javax.servlet.http.HttpServletResponse} object.
	 * @return boolean true indicating success, false otherwise.
	 * @throws IOException      .
	 * @throws ServletException .
	 */
	private boolean doPostEndpointQuery(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		Set<String> validClientIps = new HashSet<String>();
		if (getValidClientIpsForClient(request.getRemoteAddr(), validClientIps)) {
			StringBuilder buffer2 = new StringBuilder();
			buffer2.append(getIpStringFromCollection(validClientIps.iterator()));
			if (isIpLocalhost(request.getRemoteAddr())) {
				if (!buffer2.isEmpty()) {
					buffer2.append(',');
				}
				buffer2.append(CONSTANT_LOCALHOST_IPV4_STRING);
				buffer2.append(',');
				buffer2.append(CONSTANT_LOCALHOST_IPV6_STRING);
			}
			response.getWriter().append(buffer2.toString());
			response.setStatus(HttpURLConnection.HTTP_OK);

			StringBuilder buffer1 = new StringBuilder();
			buffer1.append("doPost Get OK '");
			buffer1.append(buffer2.toString());
			buffer1.append("' to client ");
			buffer1.append(request.getRemoteAddr());
			logInfoMessageToServerLog(buffer1.toString());
			return true;
		}

		logInfoMessageToServerLog("doPost Get failed for client " + request.getRemoteAddr());
		response.setStatus(HttpURLConnection.HTTP_OK);
		return false;
	}

	/**
	 * Method implements processing for Post Set endpoint. This checks that the
	 * client user/password are valid.
	 * 
	 * @param request  client {@link javax.servlet.http.HttpServletRequest} object.
	 * @param response client {@link javax.servlet.http.HttpServletResponse} object.
	 * @return boolean true indicating success, false otherwise.
	 * @throws IOException      .
	 * @throws ServletException .
	 */
	private boolean doPostEndpointSet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		if (!isFieldListInRequest(CONSTANT_HTTP_KEYS_POST_SET, request)) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "request missing fields.");
			return false;
		}

		Map<String, StringBuilder> values = new HashMap<String, StringBuilder>();
		values.putAll(Map.ofEntries(entry(CONSTANT_HTTP_KEY_USER, new StringBuilder()),
                                entry(CONSTANT_HTTP_KEY_PASSWORD, new StringBuilder()),
                                entry(CONSTANT_HTTP_KEY_HEADER, new StringBuilder()),
				entry(CONSTANT_HTTP_KEY_PUBLIC_IP, new StringBuilder()),
				entry(CONSTANT_HTTP_KEY_TOTAL, new StringBuilder())));

		if (!getFieldValuesFromRequest(request, values) || !isNumber(values, CONSTANT_HTTP_KEY_TOTAL)) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "request bad field data.");
			return false;
		}

		if (CONSTANT_HTTP_KEY_TOTAL_MAX < Integer.parseInt(values.get(CONSTANT_HTTP_KEY_TOTAL).toString())) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "key has too many parts.");
			return false;
		}

		values.put(CONSTANT_HTTP_KEY_PART_N, new StringBuilder());
		if (!getFieldCompoundValueFromRequest(request, CONSTANT_HTTP_KEY_PART_N,
				Integer.parseInt(values.get(CONSTANT_HTTP_KEY_TOTAL).toString()),
				values.get(CONSTANT_HTTP_KEY_PART_N))) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "request bad compound field data.");
			return false;
		}

		PublicKey clientPublicKey = getKeyClientPublic(values.get(CONSTANT_HTTP_KEY_PART_N).toString());
		if (clientPublicKey == null) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "client key is bad.");
			return false;
		}
		
		String user = values.get(CONSTANT_HTTP_KEY_USER).toString();
		String password = values.get(CONSTANT_HTTP_KEY_PASSWORD).toString();

		if (!checkUserPassword(user, password)) {
			response.setStatus(HttpURLConnection.HTTP_BAD_REQUEST);
			logSevereMessageToServerLogAndRespond(response, "client user/password are bad.");
			return false;			
		}
		
		Map<String, String> data = new HashMap<String, String>();
		data.put(CONSTANT_HTTP_KEY_HEADER,
				encryptData(clientPublicKey, values.get(CONSTANT_HTTP_KEY_HEADER).toString()));
		data.put(CONSTANT_HTTP_KEY_PUBLIC_IP, encryptData(clientPublicKey, request.getRemoteAddr()));

		String encodedData = encodeData(data);
		if (encodedData == null || encodedData.isBlank()) {
			response.setStatus(HttpURLConnection.HTTP_INTERNAL_ERROR);
			logSevereMessageToServerLogAndRespond(response, "could not encode data.");
			return false;
		}

		if (!addIpToValidIps(request.getRemoteAddr())) {
			response.setStatus(HttpURLConnection.HTTP_INTERNAL_ERROR);
			logSevereMessageToServerLogAndRespond(response, "could not update internal state.");
			return false;
		}

		response.setStatus(HttpURLConnection.HTTP_OK);
		response.getWriter().append(encodedData);
		return true;
	}

	/**
	 * Method Url encodes data.
	 * 
	 * @param data name value pairs in Map to be encoded
	 * @return String of encoded data.
	 */
	private String encodeData(Map<String, String> data) {
		StringBuilder buffer = new StringBuilder();
		for (Map.Entry<String, String> entry : data.entrySet()) {
			buffer.append(!buffer.isEmpty() ? "&" : "");
			buffer.append(URLEncoder.encode(entry.getKey().toString(), StandardCharsets.UTF_8));
			buffer.append("=");
			buffer.append(URLEncoder.encode(entry.getValue().toString(), StandardCharsets.UTF_8));
		}
		return buffer.toString();
	}

	/**
	 * Performs data encryption and returns encrypted String of plain-text in
	 * parameter plainText using the publicKey {@link java.security.PublicKey}
	 * parameter.
	 * 
	 * @param publicKey {@link java.security.PublicKey} to be used to encrypt
	 *                  plain-text parameter.
	 * @param plainText plain text to be encrypted.
	 * @return String containing encrypted data.
	 */
	private String encryptData(PublicKey publicKey, String plainText) {
		try {
			Cipher cipher = Cipher.getInstance(CONSTANT_KEY_ALGORITHM_RSA);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
		} catch (Exception exception) {
			logExceptionToServerLog(exception);
		}

		return null;
	}

	/**
	 * Method extracts list of values in the values parameter keySet from the
	 * parameter request. Each value is transformed into plain-text and is written
	 * into the corresponding values Entry pair. True is returned if success, false
	 * otherwise.
	 * 
	 * @param request client {@link javax.servlet.http.HttpServletRequest} object
	 *                containing client request data.
	 * @param values  request data is returned to client in this collection.
	 * @return boolean true indicating success, false otherwise.
	 */
	private boolean getFieldValuesFromRequest(HttpServletRequest request, Map<String, StringBuilder> values) {
		boolean result = true;
		for (Map.Entry<String, StringBuilder> value : values.entrySet()) {
			try {
				String plainText = decryptData(_serverPrivateKey, request.getParameter(value.getKey()));
				value.getValue().append(plainText);
			} catch (Exception exception) {
				logExceptionToServerLog(exception);
				result = false;
			}
		}
		return result;
	}

	/**
	 * Method extracts a compound value from client request data.
	 * 
	 * @param request client {@link javax.servlet.http.HttpServletRequest} object
	 *                containing client request data.
	 * @param prefix  prefix string for each part of compound value.
	 * @param count   total number of compound parts.
	 * @param buffer  compound request data is returned to client in this parameter.
	 * @return boolean true indicating success, false otherwise.
	 */
	private boolean getFieldCompoundValueFromRequest(HttpServletRequest request, String prefix, int count,
			StringBuilder buffer) {
		StringBuilder result = new StringBuilder();
		for (int i = 0; i < count; i++) {
			try {
				result.append(decryptData(_serverPrivateKey, request.getParameter(prefix + i)));
			} catch (Exception exception) {
				logExceptionToServerLog(exception);
				return false;
			}
		}
		buffer.append(result.toString());
		return true;
	}

	/**
	 * Method converts a Collection of Ip strings into a single comma delimited list
	 * of Ips.
	 * 
	 * @param Ips Iterator over sequence Ip strings.
	 * 
	 * @return String containing comma delimited list of Ip values.
	 */
	private String getIpStringFromCollection(Iterator<String> Ips) {
		StringBuilder buffer = new StringBuilder();
		while (Ips.hasNext()) {
			if (!buffer.isEmpty()) {
				buffer.append(',');
			}
			buffer.append(Ips.next().trim());
		}
		return buffer.toString();
	}

	/**
	 * Method creates {@link java.security.PublicKey} object using data passed in
	 * parameter base64EncodedPublicKey.
	 * 
	 * @param base64EncodedPublicKey key encoded as String.
	 * @return PublicKey created from param base64EncodedPublicKey if success, else
	 *         null.
	 */
	private PublicKey getKeyClientPublic(String base64EncodedPublicKey) {
		Key publicKey = getKeyURI(base64EncodedPublicKey, X509EncodedKeySpec.class, "PUBLIC", "generatePublic");
		if (publicKey instanceof PublicKey) {
			return (PublicKey) publicKey;
		}
		logSevereMessageToServerLog("could not load public key");
		return null;
	}

	/**
	 * Method loads user and password from context configuration.
	 * @return true if successful, false otherwise.
	 */
	private boolean getUserPasswordCredentials() {
		String user = getServletContext().getInitParameter(CONSTANT_PARAMETER_USER);
		if (user == null ||
				user.isBlank()) {
			logSevereMessageToServerLog("user name not in context.");
			return false;
		}
		_user = user;
		
		String password = getServletContext().getInitParameter(CONSTANT_PARAMETER_PASSWORD);
		if (password == null ||
				password.isBlank()) {
			logSevereMessageToServerLog("password not in context.");
			return false;
		}
		_password = password;
		
		return true;
	}
	
	/**
	 * Method initializes the server's {@link java.security.PrivateKey}.
	 * 
	 * @return boolean indicating whether the {@link java.security.PrivateKey} was
	 *         successfully initialized.
	 */
	private boolean getKeyServerPrivate() {
		String keyURI = getServletContext().getInitParameter(CONSTANT_PARAMETER_SERVER_PRIVATE_KEY);
		if (keyURI == null) {
			logSevereMessageToServerLog("could not load server's private key location.");
			return false;
		}

		StringBuilder buffer = new StringBuilder();

		if (!loadURI(keyURI, buffer)) {
			logSevereMessageToServerLog("unable to load key URI " + keyURI + ".");
			return false;
		}

		Key privateKey = getKeyURI(buffer.toString(), PKCS8EncodedKeySpec.class, "PRIVATE", "generatePrivate");

		if (privateKey instanceof PrivateKey) {
			_serverPrivateKey = (PrivateKey) privateKey;
			return true;
		}

		logSevereMessageToServerLog("could not init private key.");
		return false;
	}

	/**
	 * Method initializes the server's {@link java.security.PublicKey}.
	 * 
	 * @return boolean indicating whether the {@link java.security.PublicKey} was
	 *         successfully initialized.
	 */
	private boolean getKeyServerPublic() {
		String keyURI = getServletContext().getInitParameter(CONSTANT_PARAMETER_SERVER_PUBLIC_KEY);
		if (keyURI == null) {
			logSevereMessageToServerLog("could not load server's public key location.");
			return false;
		}

		StringBuilder buffer = new StringBuilder();

		if (!loadURI(keyURI, buffer)) {
			logSevereMessageToServerLog("unable to load key URI " + keyURI + ".");
			return false;
		}

		Key publicKey = getKeyURI(buffer.toString(), X509EncodedKeySpec.class, "PUBLIC", "generatePublic");

		if (publicKey instanceof PublicKey) {
			_serverPublicKey = (PublicKey) publicKey;
			_serverPublicKeyBase64 = buffer.toString();
			return true;
		}

		logSevereMessageToServerLog("could not init public key.");
		return false;
	}

	/**
	 * Method loads a {@link java.security.PrivateKey} or PublicKey from a
	 * {@link javax.servlet.http.HttpServlet} Uri path.
	 * 
	 * @param base64EncodedKey {@link java.security.Key} data encoded as a base64
	 *                         string..
	 * @param keyClass         class that should be used to create
	 *                         {@link java.security.Key} object.
	 * @param pattern          pattern for removal from Key base64 text header and
	 *                         footer.
	 * @param factoryMethod    {@link java.security.KeyFactory} method name to be
	 *                         used to create {@link java.security.Key}.
	 * @return {@link java.security.Key} created if success, else null.
	 **/
	private Key getKeyURI(String base64EncodedKey, Class<?> keyClass, String pattern, String factoryMethod) {
		byte[] decoded = Base64.getDecoder()
				.decode(base64EncodedKey.toString().replaceAll("\\n", "")
						.replaceAll("-----BEGIN " + pattern + " KEY-----", "")
						.replaceAll("-----END " + pattern + " KEY-----", "").trim());

		try {
			Constructor<?> constructor1 = keyClass.getDeclaredConstructor(decoded.getClass());
			Object object = constructor1.newInstance(new Object[] { decoded });
			if (object instanceof KeySpec) {
				KeySpec keySpec = (KeySpec) object;
				Method method = _keyFactory.getClass().getDeclaredMethod(factoryMethod, KeySpec.class);
				object = method.invoke(_keyFactory, keySpec);
				if (object instanceof Key) {
					return (Key) object;
				}
			}
		} catch (Exception e) {
			logExceptionToServerLog(e);
		}

		return null;
	}

	/**
	 * Method returns a String containing stack trace from Throwable parameter t.
	 * 
	 * @param t {@link java.lang.Throwable} object containing stack trace
	 * @return String containing stack trace of throwable parameter
	 */
	private String getStackTraceAsString(Throwable t) {
		StringWriter stringWriter = new StringWriter();
		PrintWriter printWriter = new PrintWriter(stringWriter, true);
		t.printStackTrace(printWriter);
		return stringWriter.getBuffer().toString();
	}

	/**
	 * Method returns true if param ip is in list {@link _validClientIps} or if ip
	 * is localhost. The list of valid Ips that the client is allowed to view is
	 * returned in parameter validClientIps.
	 * 
	 * @param ip             String containing ip address to be tested.
	 * @param validClientIps valid Ips will be returned in this parameter.
	 * @return boolean true if ip is in list {@link _validClientIps}, false
	 *         otherwise.
	 */
	private boolean getValidClientIpsForClient(String ip, Set<String> validClientIps) {
		Set<String> buffer = new HashSet<String>();
		long nowEpochMilliseconds = Instant.now().toEpochMilli();
		synchronized (_validClientIps) {
			_validClientIps.entrySet().removeIf(entry -> (entry.getValue() < nowEpochMilliseconds));
			buffer.addAll(_validClientIps.keySet());
		}

		if (!buffer.contains(ip) && !isIpLocalhost(ip)) {
			return false;
		}

		validClientIps.addAll(buffer);
		return true;
	}

	/**
	 * Method returns boolean indicating whether Uri is the get endpoint.
	 * 
	 * @param uri contains Uri path to be tested.
	 * @return boolean indicating whether Uri is the get endpoint.
	 **/
	private boolean isEndpointGet(String uri) {
		return CONSTANT_URI_ENDPOINT_GET.compareToIgnoreCase(uri) == 0;
	}

	/**
	 * Method returns boolean indicating whether Uri is the query endpoint.
	 * 
	 * @param uri contains Uri path to be tested.
	 * @return boolean indicating whether Uri is the query endpoint.
	 **/
	private boolean isEndpointQuery(String uri) {
		return CONSTANT_URI_ENDPOINT_QUERY.compareToIgnoreCase(uri) == 0;
	}

	/**
	 * Method returns boolean indicating whether Uri is the certificate endpoint.
	 * 
	 * @param uri contains Uri path to be tested.
	 * @return boolean indicating whether Uri is the certificate endpoint.
	 **/
	private boolean isEndpointCertificate(String uri) {
		return CONSTANT_URI_ENDPOINT_CERTIFICATE.compareToIgnoreCase(uri) == 0;
	}

	/**
	 * Method returns boolean indicating whether Uri is the set endpoint.
	 * 
	 * @param uri contains uri path to be tested.
	 * @return boolean indicating whether Uri is the set endpoint.
	 **/
	private boolean isEndpointSet(String uri) {
		return CONSTANT_URI_ENDPOINT_SET.compareToIgnoreCase(uri) == 0;
	}

	/**
	 * Method checks if all fields in fields parameter are present in request
	 * object.
	 * 
	 * @param request client {@link javax.servlet.http.HttpServletRequest} object.
	 * @param fields  names of field values to be checked against request parameter.
	 * @return boolean true indicating success, false otherwise.
	 */
	private boolean isFieldListInRequest(String[] fields, HttpServletRequest request) {
		boolean result = true;

		for (String field : fields) {
			if (request.getParameter(field) == null) {
				StringBuilder buffer = new StringBuilder();
				buffer.append("missing field in request ");
				buffer.append(field);
				buffer.append(" from client ");
				buffer.append(request.getRemoteAddr());
				logSevereMessageToServerLog(buffer.toString());
				result = false;
			}
		}
		return result;
	}

	/**
	 * Method returns true if param ip is a localhost ip by comparing Ip with
	 * {@link CONSTANT_LOCALHOST_IPV4_STRING}
	 * '{@link CONSTANT_LOCALHOST_IPV4_STRING}' . and
	 * {@link CONSTANT_LOCALHOST_IPV6_STRING}
	 * '{@value CONSTANT_LOCALHOST_IPV4_STRING}'.
	 * 
	 * @param ip String containing ip address to be tested.
	 * @return boolean if ip parameter is a localhost address.
	 */
	private boolean isIpLocalhost(String ip) {
		return CONSTANT_LOCALHOST_IPV4_STRING.compareTo(ip) == 0 || CONSTANT_LOCALHOST_IPV6_STRING.compareTo(ip) == 0;
	}

	/**
	 * Method checks if corresponding value for parameter key in parameter values is
	 * a number.
	 * 
	 * @param values data to be checked.
	 * @param key    name of the item in parameter values to be checked.
	 * @return boolean true if extracted value from values is a number, false
	 *         otherwise.
	 */
	private boolean isNumber(Map<String, StringBuilder> values, String key) {
		StringBuilder buffer = values.get(key);
		if (buffer == null || buffer.toString().isBlank()) {
			return false;
		}
		try {
			Integer.parseInt(buffer.toString());
		} catch (NumberFormatException exception) {
			return false;
		}
		return true;
	}

	/**
	 * Methods checks if an Ip address is in valid IPv4 format.
	 *
	 * @param ip the Ip value to be checked.
	 * @return boolean true if param ip is in valid IPv4 format, false otherwise.
	 */
	@SuppressWarnings("unused")
	private boolean isValidIpv4Format(String ip) {
		return ip != null && !ip.isBlank() && CONSTANT_IPV4_REGEXP_PATTERN.matcher(ip).matches();
	}

	/**
	 * Method loads {@link javax.servlet.http.HttpServlet} resource indicated by
	 * parameter uri value.
	 * 
	 * @param uri    contains path to {@link javax.servlet.http.HttpServlet}
	 *               resource to be loaded.
	 * @param buffer URI contents will be returned to caller in this parameter.
	 * @return boolean true for success, false otherwise.
	 */
	private boolean loadURI(String uri, StringBuilder buffer) {
		InputStream configStream = null;

		try {
			configStream = getServletContext().getResourceAsStream(uri);

			if (configStream == null) {
				logSevereMessageToServerLog("could not load resource '" + uri + "'");
				return false;
			}
			buffer.append(new String(configStream.readAllBytes()));
			configStream.close();

			return true;
		} catch (Exception e1) {
			logExceptionToServerLog(e1);
			try {
				if (configStream != null) {
					configStream.close();
				}
			} catch (IOException e2) {
				logExceptionToServerLog(e2);
			}
		}
		return false;
	}

	/**
	 * Method to log {@link Exception} to server log.
	 * 
	 * @param exception {@link Exception} object to be logged.
	 */
	private void logExceptionToServerLog(Exception exception) {
		Logger.getLogger(IpServer.class.getName()).log(Level.SEVERE,
				"exception: " + exception.getClass().getName() + " - " + exception.getMessage());
		Logger.getLogger(IpServer.class.getName()).log(Level.SEVERE, getStackTraceAsString(exception));
	}

	/**
	 * Method to report {@link java.util.logging.Level#INFO} message to server log
	 * 
	 * @param message {@link String} containing message to be logged.
	 */
	private void logInfoMessageToServerLog(String message) {
		Logger.getLogger(IpServer.class.getName()).log(Level.INFO, "info: " + message);
	}

	/**
	 * Method to report {@link java.util.logging.Level#SEVERE} message to server log
	 * 
	 * @param message {@link String} containing message to be logged.
	 */
	private void logSevereMessageToServerLog(String message) {
		Logger.getLogger(IpServer.class.getName()).log(Level.SEVERE, "error: " + message);
	}

	/**
	 * Method to report {@link java.util.logging.Level#SEVERE} message to server log
	 * and response object.
	 * 
	 * @param response client {@link javax.servlet.http.HttpServletRequest} object.
	 * @param message  {@link String} containing message to be logged.
	 */
	private void logSevereMessageToServerLogAndRespond(HttpServletResponse response, String message) {
		try {
			response.getWriter().append(message);
			Logger.getLogger(IpServer.class.getName()).log(Level.SEVERE, "error: " + message);
		} catch (IOException exception) {
			logExceptionToServerLog(exception);
		}
	}

	/**
	 * boolean indicating whether this {@link IpServer} object is in a valid state.
	 */
	private boolean _isValid = false;

	/**
	 * {@link java.security.KeyFactory} used to generate
	 * {@link java.security.PrivateKey} in {@link _serverPrivateKey} and
	 * {@link java.security.PublicKey} objects that have been sent by clients to
	 * server.
	 */
	private KeyFactory _keyFactory = null;

	/**
	 * Server {@link java.security.PrivateKey}
	 */
	private PrivateKey _serverPrivateKey = null;

	/**
	 * Server {@link java.security.PublicKey}
	 */
	private PublicKey _serverPublicKey = null;

	/**
	 * Server Base64 representation of Server {@link java.security.PublicKey}
	 */
	private String _serverPublicKeyBase64 = null;

	/**
	 * User name to check clients.
	 */
	private String _user = null;

	/**
	 * User password to check clients.
	 */
	private String _password = null;

	/**
	 * A map of all valid client Ips along with each UTC epoch timeout value.
	 */
	final private HashMap<String, Long> _validClientIps = new HashMap<String, Long>();

	/**
	 * {@link javax.crypto.Cipher} transformation type
	 * '{@value CONSTANT_CYPHER_TRANSFORMATION}'.
	 */
	final public static String CONSTANT_CYPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_USER}'.
	 */
	final public static String CONSTANT_HTTP_KEY_USER = "user";

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_PASSWORD}'.
	 */
	final public static String CONSTANT_HTTP_KEY_PASSWORD = "password";

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_HEADER}'.
	 */
	final public static String CONSTANT_HTTP_KEY_HEADER = "header";

	/**
	 * HTTP message key prefix '{@value CONSTANT_HTTP_KEY_PART_N}' for client key
	 * substrings.
	 */
	final public static String CONSTANT_HTTP_KEY_PART_N = "key-part-";

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_PUBLIC_IP}'.
	 */
	final public static String CONSTANT_HTTP_KEY_PUBLIC_IP = "public-ip";

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_TOTAL}'.
	 */
	final public static String CONSTANT_HTTP_KEY_TOTAL = "key-part-total";

	/**
	 * HTTP message key '{@value CONSTANT_HTTP_KEY_TOTAL_MAX}'.
	 */
	final public int CONSTANT_HTTP_KEY_TOTAL_MAX = 5;

	/**
	 * Regular expression value used by regular expression to validate IPv4 Ip
	 * address format.
	 */
	final public static Pattern CONSTANT_IPV4_REGEXP_PATTERN = Pattern
			.compile("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." + "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
					+ "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." + "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

	/**
	 * {@link java.security.KeyFactory} algorithm
	 * '{@value CONSTANT_KEY_ALGORITHM_RSA}'.
	 */
	final public static String CONSTANT_KEY_ALGORITHM_RSA = "RSA";

	/**
	 * Constant containing localhost IPv4 address
	 * {@value CONSTANT_LOCALHOST_IPV4_STRING}
	 */
	final private static String CONSTANT_LOCALHOST_IPV4_STRING = "127.0.0.1";

	/**
	 * Constant containing localhost IPv6 address
	 * {@value CONSTANT_LOCALHOST_IPV6_STRING}
	 */
	final private static String CONSTANT_LOCALHOST_IPV6_STRING = "0:0:0:0:0:0:0:1";

	/**
	 * Constant for number of milliseconds in one day
	 * {@value CONSTANT_TIME_TOTAL_MS_IN_DAY}
	 */
	final private static long CONSTANT_TIME_TOTAL_MS_IN_DAY = 1000 * 60 * 60 * 24;

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_PASSWORD}'.
	 */
	final public static String CONSTANT_PARAMETER_PASSWORD = "password";
	
	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_PASSWORD}'.
	 */
	final public static String CONSTANT_PARAMETER_USER = "user";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_SERVER_PRIVATE_KEY}'.
	 */
	final public static String CONSTANT_PARAMETER_SERVER_PRIVATE_KEY = "server-private-key";

	/**
	 * Parameter constant '{@value CONSTANT_PARAMETER_SERVER_PRIVATE_KEY}'.
	 */
	final public static String CONSTANT_PARAMETER_SERVER_PUBLIC_KEY = "server-public-key";

	/**
	 * Parameter constant for the {@link javax.servlet.http.HttpServlet} set
	 * endpoint Uri '{@value CONSTANT_URI_ENDPOINT_PREFIX}'.
	 */
	final public static String CONSTANT_URI_ENDPOINT_PREFIX = "/ipserver/server/ip";

	/**
	 * Parameter constant for the {@link javax.servlet.http.HttpServlet} get
	 * endpoint Uri '{@value CONSTANT_URI_ENDPOINT_GET}'.
	 */
	final public static String CONSTANT_URI_ENDPOINT_GET = CONSTANT_URI_ENDPOINT_PREFIX + "/get";

	/**
	 * Parameter constant for the {@link javax.servlet.http.HttpServlet} query
	 * endpoint Uri '{@value CONSTANT_URI_ENDPOINT_QUERY}'.
	 */
	final public static String CONSTANT_URI_ENDPOINT_QUERY = CONSTANT_URI_ENDPOINT_PREFIX + "/query";

	/**
	 * Parameter constant for the {@link javax.servlet.http.HttpServlet} query
	 * endpoint Uri '{@value CONSTANT_URI_ENDPOINT_CERTIFICATE}'.
	 */
	final public static String CONSTANT_URI_ENDPOINT_CERTIFICATE = CONSTANT_URI_ENDPOINT_PREFIX + "/certificate";

	/**
	 * Parameter constant for the {@link javax.servlet.http.HttpServlet} set
	 * endpoint Uri '{@value CONSTANT_URI_ENDPOINT_SET}'.
	 */
	final public static String CONSTANT_URI_ENDPOINT_SET = CONSTANT_URI_ENDPOINT_PREFIX + "/set";

	/**
	 * Parameter array containing Post-Get Http message fields for use in method
	 * {@link doPostEndpointGet}.
	 */
    final public static String[] CONSTANT_HTTP_KEYS_POST_GET = new String[] { CONSTANT_HTTP_KEY_USER, CONSTANT_HTTP_KEY_PASSWORD,
			CONSTANT_HTTP_KEY_HEADER, CONSTANT_HTTP_KEY_TOTAL };

	/**
	 * Parameter array containing Post-Set Http message fields for use in method
	 * {@link doPostEndpointSet}.
	 */
	final public static String[] CONSTANT_HTTP_KEYS_POST_SET = new String[] { CONSTANT_HTTP_KEY_USER, CONSTANT_HTTP_KEY_PASSWORD,
			CONSTANT_HTTP_KEY_HEADER, CONSTANT_HTTP_KEY_PUBLIC_IP, CONSTANT_HTTP_KEY_TOTAL };
}

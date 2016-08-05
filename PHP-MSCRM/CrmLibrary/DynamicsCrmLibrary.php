<?php
class DynamicsCrmSoapHeaderInfo
{
    public $Header;
    public $Expires;
}
// include "DynamicsCrmSoapHeaderInfo.php";
class DynamicsCrmHeader {
	
	/**
	 * Gets a CRM Online SOAP header & expiration.
	 * 
	 * @return DynamicsCrmSoapHeaderInfo An object containing the SOAP header and expiration date/time of the header.
	 * @param String $username
	 *        	Username of a valid CRM user.
	 * @param String $password
	 *        	Password of a valid CRM user.
	 * @param String $url
	 *        	The Url of the CRM Online organization (https://org.crm.dynamics.com).
	 */
	public function GetHeaderOnline($username, $password, $url) {
		$url .= (substr ( $url, - 1 ) == '/' ? '' : '/');
		$urnAddress = $this->GetUrnOnline ( $url );
		$now = $_SERVER ['REQUEST_TIME'];
		
		$xml = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">";
		$xml .= "<s:Header>";
		$xml .= "<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>";
		$xml .= "<a:MessageID>urn:uuid:" . $this->getGUID () . "</a:MessageID>";
		$xml .= "<a:ReplyTo>";
		$xml .= "<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>";
		$xml .= "</a:ReplyTo>";
		$xml .= "<a:To s:mustUnderstand=\"1\">https://login.microsoftonline.com/RST2.srf</a:To>";
		$xml .= "<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<u:Timestamp u:Id=\"_0\">";
		$xml .= "<u:Created>" . gmdate ( 'Y-m-d\TH:i:s.u\Z', $now ) . "</u:Created>";
		$xml .= "<u:Expires>" . gmdate ( 'Y-m-d\TH:i:s.u\Z', strtotime ( '+60 minute', $now ) ) . "</u:Expires>";
		$xml .= "</u:Timestamp>";
		$xml .= "<o:UsernameToken u:Id=\"uuid-" . $this->getGUID () . "-1\">";
		$xml .= "<o:Username>" . $username . "</o:Username>";
		$xml .= "<o:Password>" . $password . "</o:Password>";
		$xml .= "</o:UsernameToken>";
		$xml .= "</o:Security>";
		$xml .= "</s:Header>";
		$xml .= "<s:Body>";
		$xml .= "<trust:RequestSecurityToken xmlns:trust=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">";
		$xml .= "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">";
		$xml .= "<a:EndpointReference>";
		$xml .= "<a:Address>urn:" . $urnAddress . "</a:Address>";
		$xml .= "</a:EndpointReference>";
		$xml .= "</wsp:AppliesTo>";
		$xml .= "<trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>";
		$xml .= "</trust:RequestSecurityToken>";
		$xml .= "</s:Body>";
		$xml .= "</s:Envelope>";
		
		$headersArray = array (
				"POST " . "/RST2.srf" . " HTTP/1.1",
				"Host: " . "login.microsoftonline.com",
				'Connection: Keep-Alive',
				"Content-type: application/soap+xml; charset=UTF-8",
				"Content-length: " . strlen ( $xml ) 
		);
		
		$ch = curl_init ();
		curl_setopt ( $ch, CURLOPT_URL, "https://login.microsoftonline.com/RST2.srf" );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt ( $ch, CURLOPT_TIMEOUT, 60 );
		curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt ( $ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );
		curl_setopt ( $ch, CURLOPT_HTTPHEADER, $headersArray );
		curl_setopt ( $ch, CURLOPT_POST, 1 );
		curl_setopt ( $ch, CURLOPT_POSTFIELDS, $xml );
		
		$response = curl_exec ( $ch );
		curl_close ( $ch );
		
		$responsedom = new DomDocument ();
		$responsedom->loadXML ( $response );
		
		$cipherValues = $responsedom->getElementsbyTagName ( "CipherValue" );
		$token1 = $cipherValues->item ( 0 )->textContent;
		$token2 = $cipherValues->item ( 1 )->textContent;
		
		$keyIdentiferValues = $responsedom->getElementsbyTagName ( "KeyIdentifier" );
		$keyIdentifer = $keyIdentiferValues->item ( 0 )->textContent;
		
		$tokenExpiresValues = $responsedom->getElementsbyTagName ( "Expires" );
		$tokenExpires = $tokenExpiresValues->item ( 0 )->textContent;
		
		$authHeader = new DynamicsCrmSoapHeaderInfo ();
		$authHeader->Expires = $tokenExpires;
		$authHeader->Header = $this->CreateSoapHeaderOnline ( $url, $keyIdentifer, $token1, $token2 );
		
		return $authHeader;
	}
	
	/**
	 * Gets a CRM Online SOAP header.
	 * 
	 * @return String The XML SOAP header to be used in future requests.
	 * @param String $url
	 *        	The Url of the CRM Online organization (https://org.crm.dynamics.com).
	 * @param String $keyIdentifer
	 *        	The KeyIdentifier from the initial request.
	 * @param String $token1
	 *        	The first token from the initial request.
	 * @param String $token2
	 *        	The second token from the initial request.
	 */
	function CreateSoapHeaderOnline($url, $keyIdentifer, $token1, $token2) {
		$xml = "<s:Header>";
		$xml .= "<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/xrm/2011/Contracts/Services/IOrganizationService/Execute</a:Action>";
		$xml .= "<Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<EncryptedData Id=\"Assertion0\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\" xmlns=\"http://www.w3.org/2001/04/xmlenc#\">";
		$xml .= "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\"/>";
		$xml .= "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">";
		$xml .= "<EncryptedKey>";
		$xml .= "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>";
		$xml .= "<ds:KeyInfo Id=\"keyinfo\">";
		$xml .= "<wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<wsse:KeyIdentifier EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\">" . $keyIdentifer . "</wsse:KeyIdentifier>";
		$xml .= "</wsse:SecurityTokenReference>";
		$xml .= "</ds:KeyInfo>";
		$xml .= "<CipherData>";
		$xml .= "<CipherValue>" . $token1 . "</CipherValue>";
		$xml .= "</CipherData>";
		$xml .= "</EncryptedKey>";
		$xml .= "</ds:KeyInfo>";
		$xml .= "<CipherData>";
		$xml .= "<CipherValue>" . $token2 . "</CipherValue>";
		$xml .= "</CipherData>";
		$xml .= "</EncryptedData>";
		$xml .= "</Security>";
		$xml .= "<a:MessageID>urn:uuid:" . $this->getGUID () . "</a:MessageID>";
		$xml .= "<a:ReplyTo>";
		$xml .= "<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>";
		$xml .= "</a:ReplyTo>";
		$xml .= "<a:To s:mustUnderstand=\"1\">" . $url . "XRMServices/2011/Organization.svc</a:To>";
		$xml .= "</s:Header>";
		
		return $xml;
	}
	
	/**
	 * Gets the correct URN Address based on the Online region.
	 * 
	 * @return String URN Address.
	 * @param String $url
	 *        	The Url of the CRM Online organization (https://org.crm.dynamics.com).
	 */
	function GetUrnOnline($url) {
		if (strpos ( strtoupper ( $url ), "CRM2.DYNAMICS.COM" )) {
			return "crmsam:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM4.DYNAMICS.COM" )) {
			return "crmemea:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM5.DYNAMICS.COM" )) {
			return "crmapac:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM6.DYNAMICS.COM" )) {
			return "crmoce:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM7.DYNAMICS.COM" )) {
			return "crmjpn:dynamics.com";
		}
		if (strpos ( strtoupper ( $url ), "CRM9.DYNAMICS.COM" )) {
			return "crmgcc:dynamics.com";
		}
		
		return "crmna:dynamics.com";
	}
	
	/**
	 * Gets a CRM On Premise SOAP header & expiration.
	 * 
	 * @return DynamicsCrmSoapHeaderInfo An object containing the SOAP header and expiration date/time of the header.
	 * @param String $username
	 *        	Username of a valid CRM user.
	 * @param String $password
	 *        	Password of a valid CRM user.
	 * @param String $url
	 *        	The Url of the CRM On Premise (IFD) organization (https://org.domain.com).
	 */
	function GetHeaderOnPremise($username, $password, $url) {
		$url .= (substr ( $url, - 1 ) == '/' ? '' : '/');
		$adfsUrl = $this->GetADFS ( $url );
		$now = $_SERVER ['REQUEST_TIME'];
		$urnAddress = $url . "XRMServices/2011/Organization.svc";
		$usernamemixed = $adfsUrl . "/13/usernamemixed";
		
		$xml = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\">";
		$xml .= "<s:Header>";
		$xml .= "<a:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action>";
		$xml .= "<a:MessageID>urn:uuid:" . $this->getGUID () . "</a:MessageID>";
		$xml .= "<a:ReplyTo>";
		$xml .= "<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>";
		$xml .= "</a:ReplyTo>";
		$xml .= "<Security s:mustUnderstand=\"1\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<u:Timestamp  u:Id=\"" . $this->getGUID () . "\">";
		$xml .= "<u:Created>" . gmdate ( 'Y-m-d\TH:i:s.u\Z', $now ) . "</u:Created>";
		$xml .= "<u:Expires>" . gmdate ( 'Y-m-d\TH:i:s.u\Z', strtotime ( '+60 minute', $now ) ) . "</u:Expires>";
		$xml .= "</u:Timestamp>";
		$xml .= "<UsernameToken u:Id=\"" . $this->getGUID () . "\">";
		$xml .= "<Username>" . $username . "</Username>";
		$xml .= "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">" . $password . "</Password>";
		$xml .= "</UsernameToken>";
		$xml .= "</Security>";
		$xml .= "<a:To s:mustUnderstand=\"1\">" . $usernamemixed . "</a:To>";
		$xml .= "</s:Header>";
		$xml .= "<s:Body>";
		$xml .= "<trust:RequestSecurityToken xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">";
		$xml .= "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">";
		$xml .= "<a:EndpointReference>";
		$xml .= "<a:Address>" . $urnAddress . "</a:Address>";
		$xml .= "</a:EndpointReference>";
		$xml .= "</wsp:AppliesTo>";
		$xml .= "<trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>";
		$xml .= "</trust:RequestSecurityToken>";
		$xml .= "</s:Body>";
		$xml .= "</s:Envelope>";
		
		$headers = array (
				"POST " . parse_url ( $usernamemixed, PHP_URL_PATH ) . " HTTP/1.1",
				"Host: " . parse_url ( $adfsUrl, PHP_URL_HOST ),
				'Connection: Keep-Alive',
				"Content-type: application/soap+xml; charset=UTF-8",
				"Content-length: " . strlen ( $xml ) 
		);
		
		$ch = curl_init ();
		curl_setopt ( $ch, CURLOPT_URL, $usernamemixed );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt ( $ch, CURLOPT_TIMEOUT, 60 );
		curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt ( $ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );
		curl_setopt ( $ch, CURLOPT_HTTPHEADER, $headers );
		curl_setopt ( $ch, CURLOPT_POST, 1 );
		curl_setopt ( $ch, CURLOPT_POSTFIELDS, $xml );
		
		$response = curl_exec ( $ch );
		curl_close ( $ch );
		
		$responsedom = new DomDocument ();
		$responsedom->loadXML ( $response );
		
		$cipherValues = $responsedom->getElementsbyTagName ( "CipherValue" );
		$token1 = $cipherValues->item ( 0 )->textContent;
		$token2 = $cipherValues->item ( 1 )->textContent;
		
		$keyIdentiferValues = $responsedom->getElementsbyTagName ( "KeyIdentifier" );
		$keyIdentifer = $keyIdentiferValues->item ( 0 )->textContent;
		
		$x509IssuerNames = $responsedom->getElementsbyTagName ( "X509IssuerName" );
		$x509IssuerName = $x509IssuerNames->item ( 0 )->textContent;
		
		$x509SerialNumbers = $responsedom->getElementsbyTagName ( "X509SerialNumber" );
		$x509SerialNumber = $x509SerialNumbers->item ( 0 )->textContent;
		
		$binarySecrets = $responsedom->getElementsbyTagName ( "BinarySecret" );
		$binarySecret = $binarySecrets->item ( 0 )->textContent;
		
		$created = gmdate ( 'Y-m-d\TH:i:s.u\Z', strtotime ( '-1 minute', $now ) );
		$expires = gmdate ( 'Y-m-d\TH:i:s.u\Z', strtotime ( '+5 minute', $now ) );
		$timestamp = "<u:Timestamp xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" u:Id=\"_0\"><u:Created>" . $created . "</u:Created><u:Expires>" . $expires . "</u:Expires></u:Timestamp>";
		
		$hashedDataBytes = sha1 ( $timestamp, true );
		$digestValue = base64_encode ( $hashedDataBytes );
		
		$signedInfo = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#hmac-sha1\"></SignatureMethod><Reference URI=\"#_0\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>" . $digestValue . "</DigestValue></Reference></SignedInfo>";
		$binarySecretBytes = base64_decode ( $binarySecret );
		$hmacHash = hash_hmac ( "sha1", $signedInfo, $binarySecretBytes, true );
		$signatureValue = base64_encode ( $hmacHash );
		
		$tokenExpiresValues = $responsedom->getElementsbyTagName ( "Expires" );
		$tokenExpires = $tokenExpiresValues->item ( 0 )->textContent;
		
		$authHeader = new DynamicsCrmSoapHeaderInfo ();
		$authHeader->Expires = $tokenExpires;
		$authHeader->Header = $this->CreateSoapHeaderOnPremise ( $url, $keyIdentifer, $token1, $token2, $x509IssuerName, $x509SerialNumber, $signatureValue, $digestValue, $created, $expires );
		
		return $authHeader;
	}
	
	/**
	 * Gets a CRM On Premise (IFD) SOAP header.
	 * 
	 * @return String SOAP Header XML.
	 * @param String $url
	 *        	The Url of the CRM On Premise (IFD) organization (https://org.domain.com).
	 * @param String $keyIdentifer
	 *        	The KeyIdentifier from the initial request.
	 * @param String $token1
	 *        	The first token from the initial request.
	 * @param String $token2
	 *        	The second token from the initial request.
	 * @param String $x509IssuerName
	 *        	The certificate issuer.
	 * @param String $x509SerialNumber
	 *        	The certificate serial number.
	 * @param String $signatureValue
	 *        	The hashsed value of the header signature.
	 * @param String $digestValue
	 *        	The hashed value of the header timestamp.
	 * @param String $created
	 *        	The header created date/time.
	 * @param String $expires
	 *        	The header expiration date/tim.
	 */
	function CreateSoapHeaderOnPremise($url, $keyIdentifer, $token1, $token2, $x509IssuerName, $x509SerialNumber, $signatureValue, $digestValue, $created, $expires) {
		$xml = "<s:Header>";
		$xml .= "<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/xrm/2011/Contracts/Services/IOrganizationService/Execute</a:Action>";
		$xml .= "<a:MessageID>urn:uuid:" . $this->getGUID () . "</a:MessageID>";
		$xml .= "<a:ReplyTo>";
		$xml .= "<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>";
		$xml .= "</a:ReplyTo>";
		$xml .= "<a:To s:mustUnderstand=\"1\">" . $url . "XRMServices/2011/Organization.svc</a:To>";
		$xml .= "<o:Security xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<u:Timestamp xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" u:Id=\"_0\">";
		$xml .= "<u:Created>" . $created . "</u:Created>";
		$xml .= "<u:Expires>" . $expires . "</u:Expires>";
		$xml .= "</u:Timestamp>";
		$xml .= "<xenc:EncryptedData Type=\"http://www.w3.org/2001/04/xmlenc#Element\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">";
		$xml .= "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/>";
		$xml .= "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
		$xml .= "<e:EncryptedKey xmlns:e=\"http://www.w3.org/2001/04/xmlenc#\">";
		$xml .= "<e:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">";
		$xml .= "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>";
		$xml .= "</e:EncryptionMethod>";
		$xml .= "<KeyInfo>";
		$xml .= "<o:SecurityTokenReference xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<X509Data>";
		$xml .= "<X509IssuerSerial>";
		$xml .= "<X509IssuerName>" . $x509IssuerName . "</X509IssuerName>";
		$xml .= "<X509SerialNumber>" . $x509SerialNumber . "</X509SerialNumber>";
		$xml .= "</X509IssuerSerial>";
		$xml .= "</X509Data>";
		$xml .= "</o:SecurityTokenReference>";
		$xml .= "</KeyInfo>";
		$xml .= "<e:CipherData>";
		$xml .= "<e:CipherValue>" . $token1 . "</e:CipherValue>";
		$xml .= "</e:CipherData>";
		$xml .= "</e:EncryptedKey>";
		$xml .= "</KeyInfo>";
		$xml .= "<xenc:CipherData>";
		$xml .= "<xenc:CipherValue>" . $token2 . "</xenc:CipherValue>";
		$xml .= "</xenc:CipherData>";
		$xml .= "</xenc:EncryptedData>";
		$xml .= "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
		$xml .= "<SignedInfo>";
		$xml .= "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>";
		$xml .= "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#hmac-sha1\"/>";
		$xml .= "<Reference URI=\"#_0\">";
		$xml .= "<Transforms>";
		$xml .= "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>";
		$xml .= "</Transforms>";
		$xml .= "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>";
		$xml .= "<DigestValue>" . $digestValue . "</DigestValue>";
		$xml .= "</Reference>";
		$xml .= "</SignedInfo>";
		$xml .= "<SignatureValue>" . $signatureValue . "</SignatureValue>";
		$xml .= "<KeyInfo>";
		$xml .= "<o:SecurityTokenReference xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
		$xml .= "<o:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID\">" . $keyIdentifer . "</o:KeyIdentifier>";
		$xml .= "</o:SecurityTokenReference>";
		$xml .= "</KeyInfo>";
		$xml .= "</Signature>";
		$xml .= "</o:Security>";
		$xml .= "</s:Header>";
		
		return $xml;
	}
	
	/**
	 * Gets the name of the AD FS server CRM uses for authentication.
	 * 
	 * @return String The AD FS server url.
	 * @param String $url
	 *        	The Url of the CRM On Premise (IFD) organization (https://org.domain.com).
	 */
	function GetADFS($url) {
		$ch = curl_init ();
		curl_setopt ( $ch, CURLOPT_URL, $url . "XrmServices/2011/Organization.svc?wsdl=wsdl0" );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt ( $ch, CURLOPT_TIMEOUT, 60 );
		curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
		
		$response = curl_exec ( $ch );
		curl_close ( $ch );
		
		$responsedom = new DomDocument ();
		$responsedom->loadXML ( $response );
		
		$identifiers = $responsedom->getElementsbyTagName ( "Identifier" );
		$identifier = $identifiers->item ( 0 )->textContent;
		
		return str_replace ( "http://", "https://", $identifier );
	}
	
	// http://stackoverflow.com/questions/18206851/com-create-guid-function-got-error-on-server-side-but-works-fine-in-local-usin
	function getGUID() {
		if (function_exists ( 'com_create_guid' )) {
			return com_create_guid ();
		} else {
			mt_srand ( ( double ) microtime () * 10000 ); // optional for php 4.2.0 and up.
			$charid = strtoupper ( md5 ( uniqid ( rand (), true ) ) );
			$hyphen = chr ( 45 ); // "-"
			$uuid = chr ( 123 ) . // "{"
substr ( $charid, 0, 8 ) . $hyphen . substr ( $charid, 8, 4 ) . $hyphen . substr ( $charid, 12, 4 ) . $hyphen . substr ( $charid, 16, 4 ) . $hyphen . substr ( $charid, 20, 12 ) . chr ( 125 ); // "}"
			return $uuid;
		}
	}
}

class DynamicsCrmSoapClient {
	/**
	 * Executes the SOAP request.
	 * @return String SOAP response.
	 * @param DynamicsCrmSoapHeaderInfo $authHeader
	 *        	The authenticated DynamicsCrmSoapHeaderInfo.
	 * @param String $request
	 *        	The SOAP request body.
	 * @param String $url
	 *        	The CRM URL.
	 */
	public function ExecuteSOAPRequest($authHeader, $request, $url) {
		$url = rtrim ( $url, "/" );
		$xml = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\">";
		$xml .= $authHeader->Header;
		$xml .= $request;
		$xml .= "</s:Envelope>";
		
		$headers = array (
				"POST " . "/Organization.svc" . " HTTP/1.1",
				"Host: " . str_replace ( "https://", "", $url ),
				'Connection: Keep-Alive',
				"Content-type: application/soap+xml; charset=UTF-8",
				"Content-length: " . strlen ( $xml ) 
		);
		
		$cURL = curl_init ();
		curl_setopt ( $cURL, CURLOPT_URL, $url . "/XRMServices/2011/Organization.svc" );
		curl_setopt ( $cURL, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt ( $cURL, CURLOPT_TIMEOUT, 60 );
		curl_setopt ( $cURL, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt ( $cURL, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );
		curl_setopt ( $cURL, CURLOPT_HTTPHEADER, $headers );
		curl_setopt ( $cURL, CURLOPT_POST, 1 );
		curl_setopt ( $cURL, CURLOPT_POSTFIELDS, $xml );
		
		$response = curl_exec ( $cURL );
		curl_close ( $cURL );
		
		return $response;
	}
}


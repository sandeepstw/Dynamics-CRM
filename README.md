# PHP script to call dynamics crm API
Code sample related to Microsoft Dynamics CRM

This php script can be used to make connection to microsoft dynamics online or on premise and fetch data using crm soap services. 

# Credentials required to connection online 
// CRM Online
$url = "https://yourorg.crm.dynamics.com/";
$username = "email@domain.net";
$password = "Password";

Create a object of DynamicsCrmHeader which is under /CrmLibrary/DynamicsCrmLibrary.php file. It has required soap header to connect dynamics crm online. 

$dynamicsCrmHeader = new DynamicsCrmHeader ();

In Example, we are getting list data from crm and it requires a soap request enavalop. which you can see in index.php file. 

Soap request is xml script which you can excute using soap client. 

$client = new DynamicsCrmSoapClient ();
	
$response = $client->ExecuteSOAPRequest ( $authHeader, $xml, $url );

Return response is xml format which needs to convert in document type to read data properly, using script -

$responsedom = new DomDocument ();
$responsedom->loadXML ( $response );

Once it is converted in dom object you can use php lib to read data. 

Email us on info@softechworld.com for any kind of help. 



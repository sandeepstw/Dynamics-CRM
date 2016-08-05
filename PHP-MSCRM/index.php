<?php
include 'CrmLibrary/CrmAuth.php';



// CRM Online
$url = "https://yourorg.crm.dynamics.com/";
$username = "email@domain.net";
$password = "Password";

$dynamicsCrmHeader = new DynamicsCrmHeader ();
$authHeader = $dynamicsCrmHeader->GetHeaderOnline ( $username, $password, $url );
// End CRM Online

// CRM On Premise - IFD
// $url = "https://org.domain.com/";
// //Username format could be domain\\username or username in the form of an email
// $username = "username";
// $password = "password";

// $crmAuth = new CrmAuth();
// $authHeader = $crmAuth->GetHeaderOnPremise($username, $password, $url);
// End CRM On Premise - IFD


echo "<pre>";
$listsXml=Lists( $authHeader, $url );

print_r($listsXml);
echo "</pre>";
function Lists($authHeader, $url)
{
	$xml ="<s:Body>";
    $xml .="<Execute xmlns=\"http://schemas.microsoft.com/xrm/2011/Contracts/Services\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">";
    $xml .="<request i:type=\"a:RetrieveMultipleRequest\" xmlns:a=\"http://schemas.microsoft.com/xrm/2011/Contracts\">";
    $xml .="<a:Parameters xmlns:b=\"http://schemas.datacontract.org/2004/07/System.Collections.Generic\">";
    $xml .="<a:KeyValuePairOfstringanyType>";
            $xml .="<b:key>Query</b:key>";
            $xml .="<b:value i:type=\"a:QueryExpression\">";
              $xml .="<a:ColumnSet>";
                $xml .="<a:AllColumns>true</a:AllColumns>";
                
                $xml .="<a:Columns xmlns:c=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\">";
                //  $xml .="<c:string>listname</c:string>";
				//   $xml .="<c:string>query</c:string>";
                //  $xml .="<c:string>listid</c:string>";
                $xml .="</a:Columns>";                
              $xml .="</a:ColumnSet>";
				$xml .= "<a:Criteria>";
              $xml .= "<a:Conditions />";
            //   $xml .= "<a:ConditionExpression >";
            //   $xml .= "<a:AttributeName>statuscode</a:AttributeName>";
            //   $xml .= "<a:Operator>Equal</a:Operator>";
            //   $xml .= "<a:Values xmlns:c=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\">";
            //   $xml .= "<c:anyType i:type=\"d:string\" xmlns:d=\"http://www.w3.org/2001/XMLSchema\">0</c:anyType>";
            //   $xml .= "</a:Values>";
            //   $xml .= "</a:ConditionExpression>";
            //  $xml .= "</a:Conditions>";
               $xml .= "<a:FilterOperator>And</a:FilterOperator>";
               $xml .= "<a:Filters />";
               $xml .= "</a:Criteria>";
              $xml .="<a:Distinct>false</a:Distinct>";
              $xml .="<a:EntityName>list</a:EntityName>";
              $xml .="<a:LinkEntities />";
              $xml .="<a:Orders />";
              $xml .="<a:PageInfo>";
                $xml .="<a:Count>0</a:Count>";
                $xml .="<a:PageNumber>0</a:PageNumber>";
                $xml .="<a:PagingCookie i:nil=\"true\" />";
                $xml .="<a:ReturnTotalRecordCount>false</a:ReturnTotalRecordCount>";
              $xml .="</a:PageInfo>";
              $xml .="<a:NoLock>false</a:NoLock>";
            $xml .="</b:value>";
          $xml .="</a:KeyValuePairOfstringanyType>";
        $xml .="</a:Parameters>";
        $xml .="<a:RequestId i:nil=\"true\" />";
        $xml .="<a:RequestName>RetrieveMultiple</a:RequestName>";
      $xml .="</request>";
    $xml .="</Execute>";
  $xml .="</s:Body>";
  
	$client = new DynamicsCrmSoapClient ();
	
	$response = $client->ExecuteSOAPRequest ( $authHeader, $xml, $url );
	//echo $response;
	$responsedom = new DomDocument ();
	$responsedom->loadXML ( $response );
	
	$jsonData = "";
	
	
	$values = $responsedom->getElementsbyTagName ("Entity" );
	
	$listArray = array();
	foreach ( $values as $value ) {
	
		$objArray=array();
		foreach ( $value->firstChild->getElementsbyTagName("KeyValuePairOfstringanyType") as $KeyValuePairOfstringanyType ) 
		{
			
			$objArray[$KeyValuePairOfstringanyType->firstChild->textContent] = $KeyValuePairOfstringanyType->lastChild->textContent;
			
		}
		
		$listArray[]=$objArray;
		
	}
	
	return $listArray ;
}


	

?>

